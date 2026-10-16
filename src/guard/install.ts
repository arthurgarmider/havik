import { chmod, copyFile, mkdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { readTextOrNull } from '../core/fs'
import { asArray, asRecord } from '../core/json'
import { packageRoot } from '../core/paths'
import type { Result } from '../core/types'

type Settings = Record<string, any>

export const TOOL_MATCHER = 'Read|Edit|Write|MultiEdit|NotebookEdit|Glob|Grep|Bash|WebFetch|mcp__.*'
export const MIN_CLAUDE_VERSION = '2.1.251'
// havik/guard.js is what 0.4.0 installed; it must still be recognised so a re-install replaces it.
// Forward or backward slashes: the same hooks on Windows.
const GUARD_COMMAND = /dist[\\/]guard\.js|havik[\\/]guard\.m?js|src[\\/]guard[\\/]hook\.ts|\.havik[\\/]bin[\\/]havik(?:\.exe)?"? hook/

export const guardScript = (): string => join(packageRoot(), 'dist', 'guard.js')
export const hookCommand = (node: string, script: string, agent?: string): string => `"${node}" "${script}"${agent ? ` --agent ${agent}` : ''}`

// The standalone program runs its own hook: `"…/.havik/bin/havik" hook --agent codex`.
export const binaryHookCommand = (binary: string, agent?: string): string => `"${binary}" hook${agent ? ` --agent ${agent}` : ''}`

// Built with bun build --compile, the program's modules live in Bun's embedded file system, not on disk.
export const isStandalone = (): boolean => import.meta.url.includes('$bunfs') || import.meta.url.includes('~BUN')

// The hooks run a copy of the program in the havik home, so they keep working wherever the download is moved or deleted.
export const placeBinary = async (home: string): Promise<string> => {
  const to = join(home, 'bin', process.platform === 'win32' ? 'havik.exe' : 'havik')
  await mkdir(dirname(to), { recursive: true })
  await copyFile(process.execPath, to)
  await chmod(to, 0o755)
  return to
}

// Where each agent reads its hooks, which events havik listens to, and in which unit the agent counts the timeout.
export interface HookTarget {
  readonly agent: string
  readonly name: string
  readonly file: (home: string) => string
  readonly events: readonly { readonly event: string; readonly matcher?: string }[]
  readonly timeout: number
  readonly note?: string
  // Cursor lists hooks flat ({command, timeout}) under a versioned file; the others nest them as Claude Code does.
  readonly layout?: 'flat'
  // What shows the agent is set up here, for --agent all: a file under home, or a program on the PATH.
  readonly setUp: { readonly paths: readonly string[]; readonly bins?: readonly string[] }
}

export const TARGETS: Readonly<Record<string, HookTarget>> = {
  'claude-code': {
    agent: 'claude-code', name: 'Claude Code', file: home => join(home, '.claude', 'settings.json'), timeout: 5, setUp: { paths: ['.claude'], bins: ['claude'] },
    events: [{ event: 'PreToolUse', matcher: TOOL_MATCHER }, { event: 'PostToolUse', matcher: TOOL_MATCHER }, { event: 'SessionStart' }, { event: 'UserPromptSubmit' }, { event: 'Stop' }],
  },
  codex: {
    agent: 'codex', name: 'Codex', file: home => join(home, '.codex', 'hooks.json'), timeout: 5, setUp: { paths: ['.codex'], bins: ['codex'] },
    events: [{ event: 'PreToolUse' }, { event: 'PostToolUse' }, { event: 'SessionStart' }, { event: 'UserPromptSubmit' }, { event: 'Stop' }],
    note: 'Codex runs new hooks only after you trust them: type /hooks in Codex once.',
  },
  cursor: {
    agent: 'cursor', name: 'Cursor', file: home => join(home, '.cursor', 'hooks.json'), timeout: 5, layout: 'flat', setUp: { paths: ['.cursor'], bins: ['cursor'] },
    // Only after-hooks: Cursor's before-hooks decide permission, and an empty answer there would block the action.
    events: [{ event: 'afterShellExecution' }, { event: 'afterFileEdit' }, { event: 'afterMCPExecution' }, { event: 'afterAgentResponse' }],
    note: 'In Cursor havik records to the audit only: Cursor shows no message from a hook that does not decide permission. Read it with: havik audit',
  },
  'gemini-cli': {
    // Antigravity also creates ~/.gemini: Gemini CLI is set up only with its settings file or its program.
    agent: 'gemini-cli', name: 'Gemini CLI', file: home => join(home, '.gemini', 'settings.json'), timeout: 5000, setUp: { paths: ['.gemini/settings.json'], bins: ['gemini'] },
    events: [{ event: 'BeforeTool', matcher: '.*' }, { event: 'AfterTool', matcher: '.*' }, { event: 'SessionStart' }, { event: 'BeforeAgent' }, { event: 'AfterAgent' }],
  },
}

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
      .filter(g => !isGuardHook(g))
      .map(g => (Array.isArray(asRecord(g)['hooks']) ? { ...g, hooks: g.hooks.filter((h: unknown) => !isGuardHook(h)) } : g))
      .filter(g => !Array.isArray(asRecord(g)['hooks']) || g.hooks.length > 0)
    if (kept.length > 0) hooks[event] = kept
  }
  const { hooks: _removed, ...rest } = settings
  return Object.keys(hooks).length > 0 ? { ...rest, hooks } : rest
}

export const withGuardFor = (target: HookTarget, settings: Settings, command: string): Settings => {
  const base = withoutGuard(settings)
  const hooks: Settings = { ...asRecord(base['hooks']) }
  for (const { event, matcher } of target.events) {
    const entry = target.layout === 'flat' ? { command, timeout: target.timeout } : { ...(matcher ? { matcher } : {}), hooks: [{ type: 'command', command, timeout: target.timeout }] }
    hooks[event] = [...asArray(hooks[event]), entry]
  }
  return target.layout === 'flat' ? { version: 1, ...base, hooks } : { ...base, hooks }
}

export const withGuard = (settings: Settings, command: string): Settings => withGuardFor(TARGETS['claude-code'], settings, command)

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
  const odd = hooks !== undefined && (typeof hooks !== 'object' || Array.isArray(hooks) || Object.values(hooks).some(groups => !Array.isArray(groups)))
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

// Whether this settings file runs havik's hook: what `guard status` says for agents other than Claude Code.
export const hasGuard = async (file: string): Promise<boolean> => {
  const read = await readSettings(file)
  if (!read.ok || !read.value.existed) return false
  // Nested (Claude Code, Codex, Gemini CLI) or flat (Cursor).
  return Object.values(asRecord(read.value.settings['hooks'])).some(groups => asArray(groups).some(g => isGuardHook(g) || asArray(asRecord(g)['hooks']).some(isGuardHook)))
}

export const installGuard = async (file: string, command: string, now = new Date(), target: HookTarget = TARGETS['claude-code']): Promise<Result<{ backup?: string }>> => {
  const current = await readSettings(file)
  if (!current.ok) return current
  return save(file, withGuardFor(target, current.value.settings, command), current.value.existed, now)
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
