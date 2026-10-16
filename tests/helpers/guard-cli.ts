import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ROOT } from './scan-cli'

// HAVIK_GUARD lets CI run the same assertions against the built bundle (node dist/guard.js).
const GUARD = (process.env.HAVIK_GUARD ?? 'bun src/guard/hook.ts').split(' ')

export interface Sandbox { readonly home: string; readonly havik: string; readonly project: string; readonly env: Record<string, string> }
export interface HookRun { readonly code: number; readonly stdout: string; readonly stderr: string; readonly message?: string }

// A fake HOME, HAVIK_HOME and TMPDIR, so the hook never touches the real ones and HOME is not under an authorized temp dir.
export async function withSandbox<T>(run: (s: Sandbox) => Promise<T>): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), 'havik-guard-'))
  const s = { home: join(root, 'home'), havik: join(root, 'havik'), project: join(root, 'home', 'proj') }
  await mkdir(s.project, { recursive: true })
  await mkdir(join(root, 'tmp'), { recursive: true })
  try {
    return await run({ ...s, env: { HOME: s.home, HAVIK_HOME: s.havik, TMPDIR: join(root, 'tmp') } })
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

export async function runHook(input: string | object, env: Record<string, string>): Promise<HookRun> {
  const proc = Bun.spawn(GUARD, { cwd: ROOT, stdin: 'pipe', stdout: 'pipe', stderr: 'pipe', env: { ...process.env, ...env } })
  proc.stdin.write(typeof input === 'string' ? input : JSON.stringify(input))
  proc.stdin.end()
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  const code = await proc.exited
  let message: string | undefined
  try {
    message = stdout.trim() ? JSON.parse(stdout).systemMessage : undefined
  } catch {
    message = undefined
  }
  return { code, stdout, stderr, message }
}

export const hookEvent = (s: Sandbox, over: Record<string, unknown>) => ({
  session_id: 'sess-1', transcript_path: '/dev/null', cwd: s.project, permission_mode: 'default', hook_event_name: 'PreToolUse', ...over,
})

export async function auditOf(s: Sandbox, session = 'sess-1'): Promise<any[]> {
  const text = await readFile(join(s.havik, 'audit', `${session}.jsonl`), 'utf8').catch(() => '')
  return text.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
}
