import * as yaml from 'js-yaml'
import { createHash } from 'crypto'
import { readdir } from 'node:fs/promises'
import { join, resolve } from 'path'
import { trace } from '../core/trace'
import { analyzeSkill } from '../core/skill-analyzer'
import { findFiles, readText, readTextOrNull } from '../core/fs'
import { asRecord } from '../core/json'
import { isInside } from '../core/paths'
import type { AgentInventory, Finding, Rule, Result, Capability, Proof } from '../core/types'

const parsePermissions = (skillMd: string): Set<Capability> => {
  const permsSection = skillMd.split('## Permissions')[1]
  if (!permsSection) return new Set()
  const lines = permsSection.split('\n').filter(l => l.startsWith('- '))
  return new Set(lines.map(l => l.replace('- ', '').trim()) as Capability[])
}

async function hashSkillDir(skillPath: string): Promise<string> {
  const hash = createHash('sha256')
  for (const f of await listSourceFiles(skillPath)) {
    hash.update(await readText(f))
  }
  return hash.digest('hex')
}

function listSourceFiles(skillPath: string): Promise<string[]> {
  return findFiles('**/*.{ts,js,py}', skillPath, { absolute: true })
}

export const detectOpenClaw = trace(
  'detectOpenClaw',
  async (basePath: string): Promise<boolean> => {
    const text = await readTextOrNull(join(basePath, 'config.yaml'))
    if (text === null) return false
    try {
      const config = yaml.load(text) as Record<string, unknown>
      return 'skills_dir' in config || 'bind_address' in config
    } catch {
      return false
    }
  }
)

export const discoverOpenClaw = trace(
  'discoverOpenClaw',
  async (basePath: string): Promise<Result<AgentInventory>> => {
    try {
      const configPath = join(basePath, 'config.yaml')
      const configText = await readTextOrNull(configPath)
      if (configText === null) {
        return { ok: false, error: `config.yaml not found at ${basePath}` }
      }

      const config = asRecord(yaml.load(configText))
      const warnings: string[] = []

      // skills_dir is read from the scanned tree, so it may not lead out of the scan root.
      const configured = typeof config['skills_dir'] === 'string' ? config['skills_dir'] : 'skills'
      const skillsDir = resolve(basePath, configured)
      const contained = isInside(basePath, skillsDir)
      if (!contained) warnings.push(`Ignored skills_dir "${configured}" in ${configPath}: it points outside ${basePath}; scan that directory directly to check it`)
      const entries = contained ? await readdir(skillsDir, { withFileTypes: true }).catch(() => []) : []
      // A skill directory that is a symlink could be any directory on this machine; it is skipped, not followed.
      for (const e of entries.filter(e => e.isSymbolicLink() && !e.name.startsWith('.'))) warnings.push(`Skipped skill ${e.name} in ${skillsDir}: it is a symlink, and havik does not follow symlinks`)
      const skillNames = entries.filter(e => !e.isSymbolicLink()).map(e => e.name).filter(n => !n.startsWith('.')).sort()

      const skills = await Promise.all(
        skillNames.map(async name => {
          const skillPath = join(skillsDir, name)
          const skillMdPath = join(skillPath, 'SKILL.md')
          const skillMd = await readTextOrNull(skillMdPath)
          const declared: string[] = skillMd === null ? [] : [...parsePermissions(skillMd)]

          const sourceFiles = await listSourceFiles(skillPath)
          const hash = await hashSkillDir(skillPath)

          return {
            name,
            path: skillPath,
            hash,
            manifest: { declared },
            sourceFiles,
          }
        })
      )

      return {
        ok: true,
        value: {
          framework: 'openclaw',
          agents: [
            {
              name: 'openclaw',
              configPath,
              bindAddress: config['bind_address'],
              port: config['port'],
            },
          ],
          skills,
          mcpServers: [],
          warnings,
        },
      }
    } catch (error) {
      return { ok: false, error: `Discovery failed: ${error}` }
    }
  }
)

let findingCounter = 0
const nextId = (prefix: string) => `${prefix}-${String(++findingCounter).padStart(3, '0')}`

async function buildProofFromConfig(configPath: string, snippet: string): Promise<Proof> {
  const text = await readText(configPath)
  const lines = text.split('\n')
  const lineNum = lines.findIndex(l => l.includes('bind_address')) + 1
  return {
    file: configPath,
    line: lineNum > 0 ? lineNum : 1,
    snippet,
    safeToDisplay: true,
  }
}

export const analyzeOpenClaw = trace(
  'analyzeOpenClaw',
  async (inventory: AgentInventory, rules: readonly Rule[]): Promise<Result<readonly Finding[]>> => {
    try {
      findingCounter = 0
      const findings: Finding[] = []

      // Check exposed bind address
      for (const agent of inventory.agents) {
        if (agent.bindAddress === '0.0.0.0') {
          const configPath = agent.configPath
          const proof = await buildProofFromConfig(configPath, 'bind_address: "0.0.0.0"')
          findings.push({
            id: nextId('EX'),
            ruleId: 'exposed-bind-address',
            severity: 'critical',
            confidence: 'high',
            owasp: 'ASI05',
            description: 'Agent is bound to 0.0.0.0, exposing it on all network interfaces',
            proof,
          })
        }
      }

      for (const skill of inventory.skills) {
        const declared = new Set<Capability>((skill.manifest?.['declared'] as Capability[] | undefined) ?? [])
        const analyzed = await analyzeSkill({ name: skill.name, dir: skill.path, declared }, rules)
        if (analyzed.ok) findings.push(...analyzed.value)
      }

      return { ok: true, value: findings }
    } catch (error) {
      return { ok: false, error: `Analysis failed: ${error}` }
    }
  }
)
