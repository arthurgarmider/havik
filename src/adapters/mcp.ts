import { basename, join } from 'path'
import { trace } from '../core/trace'
import { readTextOrNull } from '../core/fs'
import { asRecord } from '../core/json'
import { containsSecret, redactSecrets } from '../core/redact'
import { isDangerousExec } from '../core/shell-patterns'
import type { Finding, McpSecret, McpServerInfo, Result } from '../core/types'

const PROMPT_INJECTION_PATTERNS = /ignore previous|disregard instructions|forget your|system prompt/i
const INLINE_CODE = /\b(?:python3?|node|deno|bun|ruby|perl|php)\s+(?:-c|-e|-p|--eval|--print)\b/
const SECRET_FLAG = /^--?(?:password|passwd|pwd|token|secret|api[-_]?key|auth(?:orization)?|bearer|credential)s?$/i
const EXACT_NPM_VERSION = /^(?:@[^/]+\/)?[^@/]+@\d[\w.+-]*$/

const CONFIG_LOCATIONS = [
  '.mcp.json',
  '.claude.json',
  '.claude/settings.json',
  '.cursor/mcp.json',
  'config.json',
  'settings.json',
]

const transportOf = (cfg: Record<string, unknown>): McpServerInfo['transport'] => {
  const explicit = String(cfg['transport'] ?? cfg['type'] ?? '')
  const remote = ['sse', 'http', 'streamable-http'].includes(explicit) || (!cfg['command'] && typeof cfg['url'] === 'string')
  return remote ? 'sse' : 'stdio'
}

// A value that follows a secret-looking flag is redacted whatever it looks like.
const redactArgs = (args: string[]): string[] =>
  args.map((arg, i) => {
    const assigned = /^(--?[\w-]+)=/.exec(arg)
    if (assigned && SECRET_FLAG.test(assigned[1])) return `${assigned[1]}=[REDACTED]`
    return i > 0 && SECRET_FLAG.test(args[i - 1]) ? '[REDACTED]' : redactSecrets(arg)
  })

// Values are inspected here and then dropped: only key names and redacted text leave this function.
export const parseMcpServers = (configPath: string, text: string, entries: unknown): McpServerInfo[] => {
  const lines = text.split('\n')
  return Object.entries(asRecord(entries)).map(([name, raw]) => {
    const cfg = asRecord(raw)
    const env = asRecord(cfg['env'])
    const headers = asRecord(cfg['headers'])
    const secrets: McpSecret[] = [
      ...Object.entries(env).filter(([k, v]) => typeof v === 'string' && containsSecret(`${k}=${v}`)).map(([key]) => ({ kind: 'env' as const, key })),
      ...Object.entries(headers).filter(([, v]) => typeof v === 'string' && containsSecret(v)).map(([key]) => ({ kind: 'header' as const, key })),
    ]
    const line = lines.findIndex(l => l.includes(`"${name}"`)) + 1
    return {
      name,
      configPath,
      transport: transportOf(cfg),
      version: cfg['version'] as string | undefined,
      command: typeof cfg['command'] === 'string' ? cfg['command'] : undefined,
      args: Array.isArray(cfg['args']) ? redactArgs(cfg['args'].map(String)) : undefined,
      url: typeof cfg['url'] === 'string' ? redactSecrets(cfg['url']) : undefined,
      envKeys: Object.keys(env),
      secrets,
      line: line > 0 ? line : undefined,
    }
  })
}

export const mergeMcpServers = (...lists: ReadonlyArray<readonly McpServerInfo[]>): McpServerInfo[] => {
  const seen = new Set<string>()
  return lists.flat().filter(s => {
    const key = `${s.configPath}\0${s.name}`
    return seen.has(key) ? false : (seen.add(key), true)
  })
}

const readServers = async (configPath: string): Promise<McpServerInfo[]> => {
  const text = await readTextOrNull(configPath)
  if (text === null) return []
  try {
    const parsed = JSON.parse(text)
    return parsed.mcpServers ? parseMcpServers(configPath, text, parsed.mcpServers) : []
  } catch {
    return []
  }
}

export const detectMcp = trace(
  'detectMcp',
  async (basePath: string): Promise<boolean> => {
    for (const loc of CONFIG_LOCATIONS) {
      if ((await readServers(join(basePath, loc))).length > 0) return true
    }
    return false
  }
)

export const discoverMcp = trace(
  'discoverMcp',
  async (basePath: string): Promise<Result<McpServerInfo[]>> => {
    try {
      const found = mergeMcpServers(...(await Promise.all(CONFIG_LOCATIONS.map(loc => readServers(join(basePath, loc))))))
      return found.length > 0 ? { ok: true, value: found } : { ok: false, error: 'No MCP config found' }
    } catch (error) {
      return { ok: false, error: `Discovery failed: ${error}` }
    }
  }
)

let findingCounter = 0
const nextId = (prefix: string) => `${prefix}-${String(++findingCounter).padStart(3, '0')}`

const commandLine = (server: McpServerInfo): string => [server.command, ...(server.args ?? [])].filter(Boolean).join(' ')

const unpinnedNpmPackage = (server: McpServerInfo): string | undefined => {
  if (!server.command || basename(server.command) !== 'npx') return undefined
  const args = server.args ?? []
  if (!args.some(a => a === '-y' || a === '--yes')) return undefined
  const pkg = args.find(a => !a.startsWith('-'))
  return pkg !== undefined && !EXACT_NPM_VERSION.test(pkg) ? pkg : undefined
}

const checkServer = (server: McpServerInfo): Finding[] => {
  const proof = (snippet: string): Finding['proof'] => ({ file: server.configPath, line: server.line ?? 1, snippet, safeToDisplay: true })
  const make = (f: Omit<Finding, 'id'>): Finding => ({ id: nextId('MCP'), ...f })
  const findings: Finding[] = []

  if (PROMPT_INJECTION_PATTERNS.test(server.name.toLowerCase())) {
    findings.push(make({
      ruleId: 'prompt-injection-risk', severity: 'high', confidence: 'medium', owasp: 'ASI01',
      description: `MCP server name "${server.name}" contains prompt injection patterns`,
      proof: proof(server.name),
    }))
  }

  for (const secret of server.secrets ?? []) {
    findings.push(secret.kind === 'header'
      ? make({
          ruleId: 'hardcoded-mcp-auth-token', severity: 'critical', confidence: 'high', owasp: 'ASI03',
          description: `MCP server "${server.name}" contains hardcoded auth token in header "${secret.key}"`,
          proof: proof(`${secret.key}: [REDACTED]`),
        })
      : make({
          ruleId: 'hardcoded-mcp-env-secret', severity: 'critical', confidence: 'high', owasp: 'ASI03',
          description: `MCP server "${server.name}" has a hardcoded credential in env var "${secret.key}"`,
          proof: proof(`${secret.key}=[REDACTED]`),
        }))
  }

  if (server.url && /^https?:\/\//i.test(server.url) && !(/localhost|127\.0\.0\.1/).test(server.url)) {
    findings.push(make({
      ruleId: 'http-mcp-server', severity: 'high', confidence: 'high', owasp: 'ASI04',
      description: `MCP server "${server.name}" uses non-localhost HTTP endpoint — data sent externally`,
      proof: proof(server.url),
    }))
  }

  const cmd = commandLine(server)
  if (isDangerousExec(cmd)) {
    findings.push(make({
      ruleId: 'mcp-dangerous-command', severity: 'critical', confidence: 'high', owasp: 'ASI02',
      description: `MCP server "${server.name}" runs a dangerous command`,
      proof: proof(cmd.slice(0, 120)),
    }))
  } else if (INLINE_CODE.test(cmd)) {
    findings.push(make({
      ruleId: 'mcp-inline-code', severity: 'medium', confidence: 'medium', owasp: 'ASI02',
      description: `MCP server "${server.name}" runs inline interpreter code that cannot be reviewed`,
      proof: proof(cmd.slice(0, 120)),
    }))
  }

  const unpinned = unpinnedNpmPackage(server)
  if (unpinned) {
    findings.push(make({
      ruleId: 'mcp-unpinned-package', severity: 'low', confidence: 'high', owasp: 'ASI04',
      description: `MCP server "${server.name}" auto-installs an unpinned npm package (${unpinned})`,
      proof: proof(cmd.slice(0, 120)),
    }))
  }

  return findings
}

export const analyzeMcp = trace(
  'analyzeMcp',
  (servers: readonly McpServerInfo[]): Result<readonly Finding[]> => {
    try {
      findingCounter = 0
      return { ok: true, value: servers.flatMap(checkServer) }
    } catch (error) {
      return { ok: false, error: `Analysis failed: ${error}` }
    }
  }
)
