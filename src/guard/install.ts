import { copyFile, mkdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { readTextOrNull } from '../core/fs'
import { asArray, asRecord } from '../core/json'
import { packageRoot } from '../core/paths'
import type { Result } from '../core/types'

type Settings = Record<string, any>

export const TOOL_MATCHER = 'Read|Edit|Write|MultiEdit|NotebookEdit|Glob|Grep|Bash|WebFetch|mcp__.*'
export const MIN_CLAUDE_VERSION = '2.1.251'
const EVENTS = ['PreToolUse', 'PostToolUse', 'SessionStart'] as const
// havik/guard.js is what 0.4.0 installed; it must still be recognised so a re-install replaces it.
const GUARD_COMMAND = /dist\/guard\.js|havik\/guard\.m?js|src\/guard\/hook\.ts/

export const guardScript = (): string => join(packageRoot(), 'dist', 'guard.js')
export const hookCommand = (node: string, script: string): string => `"${node}" "${script}"`

// The hooks run a copy of the self-contained guard bundle in the havik home, so they survive npx clearing its cache.
// .mjs, because the bundle is an ES module and no package.json next to the copy says so.
export const placeGuard = async (from: string, home: string): Promise<string> => {
  const to = join(home, 'guard.mjs')
  await mkdir(home, { recursive: true })
  await copyFile(from, to)
  return to
}
const isGuardHook = (hook: unknown): boolean => GUARD_COMMAND.test(String(asRecord(hook)['command'] ?? ''))

// The settings without havik's hook entries. Every other hook, and any shape havik does not understand, stays as it was.
export const withoutGuard = (settings: Settings): Settings => {
  if (!settings['hooks'] || typeof settings['hooks'] !== 'object') return settings
  const hooks: Settings = {}
  for (const [event, groups] of Object.entries(settings['hooks'] as Settings)) {
    if (!Array.isArray(groups)) {
      hooks[event] = groups
      continue
    }
    const kept = groups
      .map(g => (Array.isArray(asRecord(g)['hooks']) ? { ...g, hooks: g.hooks.filter((h: unknown) => !isGuardHook(h)) } : g))
      .filter(g => !Array.isArray(asRecord(g)['hooks']) || g.hooks.length > 0)
    if (kept.length > 0) hooks[event] = kept
  }
  const { hooks: _removed, ...rest } = settings
  return Object.keys(hooks).length > 0 ? { ...rest, hooks } : rest
}

export const withGuard = (settings: Settings, command: string): Settings => {
  const base = withoutGuard(settings)
  const hooks: Settings = { ...asRecord(base['hooks']) }
  const entry = (matcher?: string) => ({ ...(matcher ? { matcher } : {}), hooks: [{ type: 'command', command, timeout: 5 }] })
  hooks['PreToolUse'] = [...asArray(hooks['PreToolUse']), entry(TOOL_MATCHER)]
  hooks['PostToolUse'] = [...asArray(hooks['PostToolUse']), entry(TOOL_MATCHER)]
  hooks['SessionStart'] = [...asArray(hooks['SessionStart']), entry()]
  return { ...base, hooks }
}

const readSettings = async (file: string): Promise<Result<{ settings: Settings; existed: boolean }>> => {
  const text = await readTextOrNull(file)
  if (text === null) return { ok: true, value: { settings: {}, existed: false } }
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    return { ok: false, error: `${file} is not valid JSON; it was left alone` }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { ok: false, error: `${file} is not a JSON object; it was left alone` }
  const hooks = (data as Settings)['hooks']
  const odd = hooks !== undefined && (typeof hooks !== 'object' || Array.isArray(hooks) || EVENTS.some(e => hooks[e] !== undefined && !Array.isArray(hooks[e])))
  if (odd) return { ok: false, error: `${file} has hooks in a shape havik does not recognise; it was left alone` }
  return { ok: true, value: { settings: data as Settings, existed: true } }
}

const save = async (file: string, settings: Settings, existed: boolean, now: Date): Promise<Result<{ backup?: string }>> => {
  try {
    const backup = existed ? `${file}.bak-${now.toISOString().replace(/[:.]/g, '-')}` : undefined
    if (backup) await copyFile(file, backup)
    await mkdir(dirname(file), { recursive: true })
    await writeFile(file, `${JSON.stringify(settings, null, 2)}\n`)
    return { ok: true, value: { backup } }
  } catch (error) {
    return { ok: false, error: `could not write ${file}: ${error}` }
  }
}

export const installGuard = async (file: string, command: string, now = new Date()): Promise<Result<{ backup?: string }>> => {
  const current = await readSettings(file)
  if (!current.ok) return current
  return save(file, withGuard(current.value.settings, command), current.value.existed, now)
}

export const uninstallGuard = async (file: string, now = new Date()): Promise<Result<{ backup?: string; removed: boolean }>> => {
  const current = await readSettings(file)
  if (!current.ok) return current
  const next = withoutGuard(current.value.settings)
  if (!current.value.existed || JSON.stringify(next) === JSON.stringify(current.value.settings)) return { ok: true, value: { removed: false } }
  const saved = await save(file, next, true, now)
  return saved.ok ? { ok: true, value: { ...saved.value, removed: true } } : saved
}

export const compareVersions = (a: string, b: string): number => {
  const [pa, pb] = [a, b].map(v => v.split('.').map(n => Number.parseInt(n, 10) || 0))
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (d !== 0) return Math.sign(d)
  }
  return 0
}

export interface GuardStatus {
  readonly installedIn: readonly string[]
  readonly missingScripts: readonly string[]
  readonly disabledBy: readonly string[]
  readonly sandbox: boolean
  readonly claudeVersion?: string
  readonly versionOk?: boolean
}

// Every settings file Claude Code would merge for a session started in `cwd`, except managed settings.
const settingsFiles = (cwd: string, home: string): string[] => {
  const files = [join(home, '.claude', 'settings.json')]
  for (let dir = cwd; ; dir = dirname(dir)) {
    files.push(join(dir, '.claude', 'settings.json'), join(dir, '.claude', 'settings.local.json'))
    if (dir === dirname(dir)) break
  }
  return [...new Set(files)]
}

export const guardStatus = async (cwd: string, home: string, claudeVersion?: string): Promise<GuardStatus> => {
  const installedIn: string[] = []
  const missingScripts: string[] = []
  const disabledBy: string[] = []
  let sandbox = false
  for (const file of settingsFiles(cwd, home)) {
    const read = await readSettings(file)
    if (!read.ok || !read.value.existed) continue
    const settings = read.value.settings
    const commands = Object.values(asRecord(settings['hooks'])).flatMap(groups => asArray(groups).flatMap(g => asArray(asRecord(g)['hooks'])))
      .filter(isGuardHook).map(h => String(asRecord(h)['command']))
    if (commands.length > 0) installedIn.push(file)
    for (const c of commands) {
      const script = c.match(/"([^"]*(?:dist\/guard\.js|src\/guard\/hook\.ts))"/)?.[1]
      if (script && !existsSync(script) && !missingScripts.includes(script)) missingScripts.push(script)
    }
    if (settings['disableAllHooks'] === true) disabledBy.push(file)
    if (asRecord(settings['sandbox'])['enabled'] === true) sandbox = true
  }
  const versionOk = claudeVersion ? compareVersions(claudeVersion, MIN_CLAUDE_VERSION) >= 0 : undefined
  return { installedIn, missingScripts, disabledBy, sandbox, claudeVersion, versionOk }
}
