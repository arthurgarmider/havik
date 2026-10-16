import { homedir, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import * as yaml from 'js-yaml'
import { withoutProcessEnv } from '../core/exfil-patterns'
import { readTextOrNull } from '../core/fs'
import { asArray, asRecord } from '../core/json'
import { isInside } from '../core/paths'
import { classifyPath, type SensitivityEntry, type SensitivityLevel, type SensitivityMap } from '../core/sensitivity'
import { AGENTS } from '../agents/registry'
import type { AgentDef, AgentPaths } from '../agents/types'
import { expandPath, tildify } from './accesses'

export const havikHome = (): string => process.env['HAVIK_HOME']?.trim() || join(homedir(), '.havik')

export interface GuardConfig {
  readonly roots: readonly string[]
  readonly allow: readonly string[]
  readonly sensitive: SensitivityMap
  readonly alertLevel: 'critical' | 'high' | 'medium'
  readonly retentionDays: number
}

const NO_ENTRIES: SensitivityMap = { critical: [], high: [], medium: [], low: [] }
export const DEFAULT_CONFIG: GuardConfig = { roots: [], allow: [], sensitive: NO_ENTRIES, alertLevel: 'high', retentionDays: 30 }

const ALERT_LEVELS = ['critical', 'high', 'medium'] as const
const expandHome = (p: string): string => expandPath(p, '/', homedir()) ?? resolve(p)
const strings = (value: unknown): string[] => asArray(value).filter((v): v is string => typeof v === 'string')
const entries = (value: unknown): SensitivityEntry[] =>
  asArray(value).map(asRecord).filter(e => typeof e['pattern'] === 'string')
    .map(e => ({ pattern: e['pattern'], reason: typeof e['reason'] === 'string' ? e['reason'] : 'listed in guard.yaml' }))

// ~/.havik/guard.yaml is optional; a file that does not parse is ignored, never fatal for a hook.
export const loadGuardConfig = async (home = havikHome()): Promise<GuardConfig> => {
  const text = await readTextOrNull(join(home, 'guard.yaml'))
  if (text === null) return DEFAULT_CONFIG
  let data: Record<string, any>
  try {
    data = asRecord(yaml.load(text))
  } catch {
    return DEFAULT_CONFIG
  }
  const sensitive = asRecord(data['sensitive'])
  const days = Number(data['retention_days'])
  return {
    roots: strings(data['roots']).map(expandHome),
    allow: strings(data['allow']).map(expandHome),
    sensitive: { critical: entries(sensitive['critical']), high: entries(sensitive['high']), medium: entries(sensitive['medium']), low: [] },
    alertLevel: ALERT_LEVELS.includes(data['alert_level']) ? data['alert_level'] : 'high',
    retentionDays: Number.isInteger(days) && days > 0 ? days : 30,
  }
}

// Ruling R5: reading a neighbouring repository or an app config is routine for an agent, so it is
// audit-only here; shell rc files and ~/.gitconfig are where a write persists access.
const DEMOTED = new Set(['~/git/', '~/.config/'])
const GUARD_HIGH: SensitivityEntry[] = [
  ...['~/.zshrc', '~/.bashrc', '~/.bash_profile', '~/.profile', '~/.zprofile'].map(pattern => ({ pattern, reason: 'Shell startup file' })),
  { pattern: '~/.gitconfig', reason: 'Git configuration, can run commands' },
]

export const guardMap = (map: SensitivityMap, config: GuardConfig): SensitivityMap => {
  const base = withoutProcessEnv(map)
  return {
    critical: [...config.sensitive.critical, ...base.critical],
    high: [...config.sensitive.high, ...GUARD_HIGH, ...base.high.filter(e => !DEMOTED.has(e.pattern))],
    medium: [...config.sensitive.medium, ...base.high.filter(e => DEMOTED.has(e.pattern)), ...base.medium],
    low: base.low,
  }
}

// The Claude Code files an agent reads constantly; the rest of ~/.claude (transcripts, credentials) stays sensitive.
const CLAUDE_ALLOWED = ['settings.json', 'settings.local.json', 'CLAUDE.md', 'skills', 'plugins', 'agents', 'commands']
// Files that sit next to secrets without being secrets; the scanner map rates the whole directory.
const NOT_A_SECRET = /^~\/\.ssh\/(?:config|known_hosts(?:\.old)?|[^/]+\.pub)$|^~\/\.aws\/config$/
// Claude Code's per-project memory notes are read and written by every session.
const MEMORY_DIR = /^~\/\.claude\/projects\/[^/]+\/memory(?:\/|$)/
const PROJECTS_DIR = /^~\/\.claude\/projects\//
// Under ~/.claude, what holds credentials or conversations stays critical; plugin data and snapshots are application data.
const CLAUDE_CRITICAL = /^~\/\.claude\/(?:\.credentials\.json$|history[^/]*$|debug\/)/
const CLAUDE_DIR = /^~\/\.claude(?:\/|$)/
// Plans and todo lists are working notes, not secrets.
const NOTES_DIR = /^~\/\.claude\/(?:plans|todos)\//
// Under ~/.claude/projects only the transcripts hold conversations; everything else a session saved there is an artifact.
const TRANSCRIPT = /\.jsonl$/

// The scanner matches `~/` patterns anywhere in a line of code; the guard sees real absolute paths, so
// a `~/` pattern must match at the home directory and nowhere else.
const classifyAbsolute = (path: string, home: string, map: SensitivityMap): { level: SensitivityLevel; reason: string } => {
  const tilde = tildify(path, home)
  for (const level of ['critical', 'high', 'medium', 'low'] as const) {
    for (const entry of map[level]) {
      if (entry.pattern.startsWith('~/')) {
        const dir = entry.pattern.replace(/\/$/, '')
        if (tilde === dir || tilde.startsWith(`${dir}/`)) return { level, reason: entry.reason }
      } else if (entry.pattern.startsWith('/')) {
        if (path === entry.pattern || path.startsWith(`${entry.pattern}/`)) return { level, reason: entry.reason }
      } else if (classifyPath(path, { critical: [], high: [], medium: [], low: [], [level]: [entry] }).level === level) {
        return { level, reason: entry.reason }
      }
    }
  }
  return { level: 'low', reason: 'No specific classification' }
}

const isClaudeCode = (agent: string | undefined): boolean => agent === undefined || agent === 'claude-code'

// A root that holds the home directory (a session started in ~ or /) would authorize every credential; it is dropped.
// The Claude Code files read all day are authorized for Claude Code only.
export const authorizedRoots = (cwd: string, memoryRoots: readonly string[], config: GuardConfig, home: string, agent?: string): string[] => [
  cwd, ...memoryRoots, ...config.roots, tmpdir(), join(havikHome(), 'cache'),
  ...(isClaudeCode(agent) ? CLAUDE_ALLOWED.map(p => join(home, '.claude', p)) : []),
].filter(root => !isInside(root, home))

export interface PolicyContext { readonly roots: readonly string[]; readonly config: GuardConfig; readonly map: SensitivityMap; readonly home: string; readonly sessionId?: string; readonly agent?: string }

const possessive = (name: string): string => (name.endsWith('s') ? `${name}'` : `${name}'s`)

// A `*` segment stands for one folder name: ~/.cursor/projects/*/agent-transcripts.
const wildcard = (prefix: string): RegExp =>
  new RegExp(`^${prefix.replace(/\/$/, '').split('/').map(seg => (seg === '*' ? '[^/]+' : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('/')}(?:/|$)`)

const under = (tilde: string, prefix: string): boolean =>
  prefix.includes('*') ? wildcard(prefix).test(tilde) : tilde === prefix || tilde.startsWith(`${prefix.replace(/\/$/, '')}/`)

// The agent whose folder of this kind holds the path; the longest match wins (~/.gemini/config is Antigravity's, not Gemini CLI's).
const ownerOf = (tilde: string, kind: keyof AgentPaths): AgentDef | undefined => {
  let best: { def: AgentDef; length: number } | undefined
  for (const def of AGENTS) {
    for (const prefix of def.paths[kind] ?? []) {
      if (under(tilde, prefix) && (!best || prefix.length > best.length)) best = { def, length: prefix.length }
    }
  }
  return best?.def
}

// What every agent keeps: its password files, its conversations, its settings, its other data. Undefined lets the rest decide.
const agentVerdict = (tilde: string, agent: string | undefined, sessionId: string | undefined): PathVerdict | undefined => {
  const secret = ownerOf(tilde, 'secrets')
  if (secret) return { level: 'critical', reason: `${possessive(secret.name)} password or key file`, authorized: false }
  const conversations = ownerOf(tilde, 'conversations')
  const settings = ownerOf(tilde, 'configs')
  const owner = conversations ?? settings ?? ownerOf(tilde, 'data')
  if (!owner) return undefined
  if (owner.id === (agent ?? 'claude-code')) {
    // Claude Code's own memory notes and transcript have rules of their own below.
    if (owner.id === 'claude-code') return undefined
    if (conversations === owner && !(sessionId && tilde.includes(sessionId))) return { level: 'critical', reason: `${possessive(owner.name)} other conversations`, authorized: false }
    return { level: 'low', reason: `${possessive(owner.name)} own files`, authorized: true }
  }
  if (conversations) return { level: 'critical', reason: `${possessive(owner.name)} conversations`, authorized: false }
  if (settings) return { level: 'critical', reason: `${possessive(owner.name)} settings, which can hold tokens`, authorized: false }
  return { level: 'medium', reason: `${owner.name} application data`, authorized: false }
}
export interface PathVerdict { readonly level: SensitivityLevel; readonly reason: string; readonly authorized: boolean }

const SECRETS_FILE = /(?:^|\/)\.env(?:\.[\w.-]+)?$|\.(?:pem|key)$/i

export const judgePath = (path: string, ctx: PolicyContext): PathVerdict => {
  if (ctx.config.allow.includes(path)) return { level: 'low', reason: 'allowed in guard.yaml', authorized: true }
  // An agent's password or key file is never "inside the project", even for a session started in that agent's folder.
  const secret = ownerOf(tildify(path, ctx.home), 'secrets')
  if (secret) return { level: 'critical', reason: `${possessive(secret.name)} password or key file`, authorized: false }
  const inside = ctx.roots.some(root => isInside(root, path))
  if (inside && SECRETS_FILE.test(path)) return { level: 'medium', reason: 'secrets file inside the project', authorized: false }
  if (inside) return { level: 'low', reason: 'inside the project', authorized: true }
  const tilde = tildify(path, ctx.home)
  const byAgent = agentVerdict(tilde, ctx.agent, ctx.sessionId)
  if (byAgent) return byAgent
  if (MEMORY_DIR.test(tilde)) return { level: 'low', reason: 'Claude Code memory notes', authorized: true }
  if (NOTES_DIR.test(tilde)) return { level: 'medium', reason: 'Claude Code working notes', authorized: false }
  if (PROJECTS_DIR.test(tilde)) {
    const own = ctx.sessionId && tilde.split('/').some(part => part === ctx.sessionId || part === `${ctx.sessionId}.jsonl`)
    if (own) return { level: 'low', reason: 'this session\'s own files', authorized: true }
    return TRANSCRIPT.test(tilde) ? { level: 'critical', reason: 'Another session\'s transcript', authorized: false } : { level: 'medium', reason: 'Files another session saved', authorized: false }
  }
  if (CLAUDE_DIR.test(tilde) && !CLAUDE_CRITICAL.test(tilde)) return { level: 'medium', reason: 'Claude Code application data', authorized: false }
  const { level, reason } = classifyAbsolute(path, ctx.home, ctx.map)
  if (NOT_A_SECRET.test(tilde) && level === 'critical') return { level: 'medium', reason: `${reason} (not itself a secret)`, authorized: false }
  return { level, reason, authorized: false }
}
