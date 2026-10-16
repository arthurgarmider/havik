import { Command, Option } from 'commander'
import { basename, dirname, join, resolve } from 'path'
import { homedir } from 'os'
import { existsSync } from 'fs'
import { loadRules } from '../core/rule-engine'
import { calculateScore } from '../core/scoring'
import { detectOpenClaw, discoverOpenClaw, analyzeOpenClaw } from '../adapters/openclaw'
import { detectMcp, discoverMcp, analyzeMcp, mergeMcpServers } from '../adapters/mcp'
import { detectGeneric, analyzeGeneric } from '../adapters/generic'
import { detectClaudeCode, discoverClaudeCode } from '../adapters/claude-code'
import { analyzeClaudeCode } from '../adapters/claude-code-analyzer'
import { formatTerminal } from '../output/terminal'
import { formatJson } from '../output/json'
import { findAgentInstalls } from '../core/discovery'
import { packageRoot } from '../core/paths'
import { findFiles } from '../core/fs'
import { dedupeAndRenumber } from '../core/findings'
import { createJudge, jevHost } from '../ai/client'
import { runAi } from '../ai/run'
import calibration from '../../data/jev-calibration.json'
import { analyzeSkill, type SkillTarget } from '../core/skill-analyzer'
import type { AgentInventory, Finding, McpServerInfo, Result, Severity, ScanResult } from '../core/types'

const RULES_DIR = join(packageRoot(), 'rules/core')
const FRAMEWORKS = ['openclaw', 'claude-code', 'mcp', 'generic']
const SEVERITIES = ['critical', 'high', 'medium', 'low']
const FORMATS = ['terminal', 'json']

// A layer that fails must say so: silence would read as "nothing found" and grade A.
const valueOrWarn = <T>(result: Result<T>, what: string, warnings: string[]): T | undefined => {
  if (result.ok) return result.value
  warnings.push(`${what} failed: ${result.error}`)
  return undefined
}

async function scanSinglePath(scanPath: string, rules: readonly import('../core/types').Rule[], opts: {
  framework?: string
}): Promise<{ findings: Finding[], inventory: AgentInventory, warnings: string[], targets: SkillTarget[] }> {
  const allFindings: Finding[] = []
  const warnings: string[] = []
  let inventory: AgentInventory = { framework: 'generic', agents: [], skills: [], mcpServers: [] }

  const useOpenClaw = !opts.framework || opts.framework === 'openclaw'
  const useMcp = !opts.framework || opts.framework === 'mcp'
  const useClaudeCode = !opts.framework || opts.framework === 'claude-code'
  const servers: McpServerInfo[] = []
  const skills = new Map<string, SkillTarget>()
  const claimed: SkillTarget[] = [] // OpenClaw skills: analysed inside analyzeOpenClaw, with their declared permissions

  if (useClaudeCode && await detectClaudeCode(scanPath)) {
    const found = valueOrWarn(await discoverClaudeCode(scanPath), `Claude Code discovery in ${scanPath}`, warnings)
    if (found) {
      warnings.push(...found.warnings)
      const ccSkills = found.skills.map(s => ({
        name: s.name,
        path: s.path,
        hash: '',
        sourceFiles: [s.path],
        manifest: { pluginSource: s.pluginSource, allowedTools: s.allowedTools },
      }))
      inventory = {
        ...inventory,
        framework: 'claude-code',
        skills: [...inventory.skills, ...ccSkills],
      }
      servers.push(...found.mcpServers)
      for (const s of found.skills) skills.set(resolve(dirname(s.path)), { name: s.name, dir: resolve(dirname(s.path)) })
      allFindings.push(...valueOrWarn(analyzeClaudeCode(found), 'Claude Code analysis', warnings) ?? [])
    }
  }

  if (useOpenClaw && await detectOpenClaw(scanPath)) {
    const found = valueOrWarn(await discoverOpenClaw(scanPath), `OpenClaw discovery in ${scanPath}`, warnings)
    if (found) {
      const { warnings: discoveryWarnings = [], ...discovered } = found
      warnings.push(...discoveryWarnings)
      inventory = discovered
      claimed.push(...discovered.skills.map(s => ({ name: s.name, dir: resolve(s.path) })))
      allFindings.push(...valueOrWarn(await analyzeOpenClaw(discovered, rules), 'OpenClaw analysis', warnings) ?? [])
    }
  }

  if (useMcp && await detectMcp(scanPath)) {
    servers.push(...valueOrWarn(await discoverMcp(scanPath), `MCP discovery in ${scanPath}`, warnings) ?? [])
  }

  const uniqueServers = mergeMcpServers(servers)
  if (uniqueServers.length > 0) {
    inventory = { ...inventory, framework: inventory.framework === 'generic' ? 'mcp' : inventory.framework, mcpServers: uniqueServers }
    allFindings.push(...valueOrWarn(analyzeMcp(uniqueServers), 'MCP analysis', warnings) ?? [])
  }

  if (useClaudeCode) {
    const claimed = new Set(inventory.framework === 'openclaw' ? inventory.skills.map(s => resolve(s.path)) : [])
    const onDisk = await findFiles('**/SKILL.md', scanPath, { dot: true, absolute: true, deep: 3 })
    const walked = onDisk.map(f => resolve(dirname(f))).filter(dir => !claimed.has(dir) && !skills.has(dir))
    for (const dir of walked) skills.set(dir, { name: basename(dir), dir })
    inventory = {
      ...inventory,
      skills: [...inventory.skills, ...walked.map(dir => ({ name: basename(dir), path: dir, hash: '', sourceFiles: [] as string[] }))],
    }
    for (const target of skills.values()) {
      allFindings.push(...valueOrWarn(await analyzeSkill(target, rules), `Analysis of skill ${target.name}`, warnings) ?? [])
    }
  }

  if (!opts.framework || opts.framework === 'generic') {
    allFindings.push(...valueOrWarn(await analyzeGeneric(scanPath), 'Generic analysis', warnings) ?? [])
  }

  return { findings: allFindings, inventory, warnings, targets: [...claimed, ...skills.values()] }
}

// The optional AI pass: it can add findings, never remove one, and a failure only becomes a warning.
async function aiPass(targets: readonly SkillTarget[]): Promise<{ findings: Finding[], warnings: string[] }> {
  if (!process.env['TYPESAFE_API_KEY']?.trim()) return { findings: [], warnings: ['--ai needs TYPESAFE_API_KEY, so the AI checks were skipped'] }
  process.stderr.write(`ai: sending redacted skill text to ${jevHost()}\n`)
  return runAi(targets, createJudge(), calibration.thresholds)
}

async function runScan(scanPath: string, opts: {
  framework?: string
  format: string
  severity?: string
  verbose: boolean
  recursive: boolean
  ai: boolean
}): Promise<ScanResult> {
  const start = Date.now()
  const rulesResult = await loadRules(RULES_DIR)
  if (!rulesResult.ok) throw new Error(`Failed to load rules: ${rulesResult.error}`)
  const rules = rulesResult.value

  const allFindings: Finding[] = []
  const warnings: string[] = []
  const targets = new Map<string, SkillTarget>()
  let mergedInventory: AgentInventory = { framework: 'generic', agents: [], skills: [], mcpServers: [] }

  if (opts.recursive) {
    process.stderr.write(`  Searching for agent installations in ${scanPath}...\n`)
    const installs = await findAgentInstalls(scanPath)
    if (installs.length === 0) {
      process.stderr.write(`  No agent installations found.\n`)
    } else {
      process.stderr.write(`  Found ${installs.length} installation(s):\n`)
      for (const inst of installs) {
        process.stderr.write(`    ${inst.path} [${inst.frameworks.join(', ')}]\n`)
      }
      process.stderr.write('\n')
    }
    for (const inst of installs) {
      const { findings, inventory, warnings: found, targets: analysed } = await scanSinglePath(inst.path, rules, opts)
      allFindings.push(...findings)
      warnings.push(...found)
      for (const t of analysed) targets.set(t.dir, t)
      const known = new Set(mergedInventory.skills.map(s => s.path))
      const agents = new Set(mergedInventory.agents.map(a => `${a.configPath}\0${a.name}`))
      mergedInventory = {
        framework: inventory.framework !== 'generic' ? inventory.framework : mergedInventory.framework,
        agents: [...mergedInventory.agents, ...inventory.agents.filter(a => !agents.has(`${a.configPath}\0${a.name}`))],
        skills: [...mergedInventory.skills, ...inventory.skills.filter(s => !known.has(s.path))],
        mcpServers: mergeMcpServers(mergedInventory.mcpServers, inventory.mcpServers),
      }
    }
  } else {
    const { findings, inventory, warnings: found, targets: analysed } = await scanSinglePath(scanPath, rules, opts)
    allFindings.push(...findings)
    warnings.push(...found)
    for (const t of analysed) targets.set(t.dir, t)
    mergedInventory = inventory
  }

  const ai = opts.ai ? await aiPass([...targets.values()]) : { findings: [], warnings: [] }
  warnings.push(...ai.warnings)

  // Score and exit code use every finding; --severity only narrows what is shown.
  const unique = dedupeAndRenumber([...allFindings, ...ai.findings])
  const filtered: Finding[] = opts.severity
    ? unique.filter(f => f.severity === (opts.severity as Severity))
    : unique

  return {
    timestamp: new Date().toISOString(),
    inventory: mergedInventory,
    findings: filtered,
    score: calculateScore(unique),
    warnings: [...new Set(warnings)],
    scanDurationMs: Date.now() - start,
  }
}

export const scanCommand = new Command('scan')
  .description('Scan an agent environment for security risks')
  .argument('[path]', 'Path to scan', homedir())
  .addOption(new Option('--framework <name>', 'Limit to specific framework').choices(FRAMEWORKS))
  .addOption(new Option('--format <type>', 'Output format').choices(FORMATS).default('terminal'))
  .addOption(new Option('--severity <level>', 'Show only findings of this severity').choices(SEVERITIES))
  .option('--verbose', 'Show full details for all severities', false)
  .option('-r, --recursive', 'Recursively search for agent installations', false)
  .option('--ai', 'Also ask TypeSafe Jev about each skill: sends redacted skill text to api.typesafe.ai and needs TYPESAFE_API_KEY', false)
  .action(async (scanPath: string, opts: {
    framework?: string
    format: string
    severity?: string
    verbose: boolean
    recursive: boolean
    ai: boolean
    }) => {
    if (!existsSync(scanPath)) {
      process.stderr.write(`Error: path does not exist: ${scanPath}\n`)
      process.exitCode = 3
      return
    }
    try {
      const result = await runScan(scanPath, opts)
      const output = opts.format === 'json' ? formatJson(result) : formatTerminal(result, opts.verbose)
      process.stdout.write(output + '\n')
      for (const warning of result.warnings) process.stderr.write(`warning: ${warning}\n`)

      const { critical, high } = result.score.findingCounts
      process.exitCode = critical > 0 ? 2 : high > 0 ? 1 : result.warnings.length > 0 ? 3 : 0
    } catch (error) {
      process.stderr.write(`Error: ${error}\n`)
      process.exitCode = 3
    }
  })
