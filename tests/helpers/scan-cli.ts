import { existsSync } from 'node:fs'
import { join } from 'path'

export const ROOT = join(import.meta.dir, '../..')
export const FIXTURES = join(import.meta.dir, '../fixtures')

// HAVIK_CLI lets CI run the same assertions against the built Node bundle.
const CLI = (process.env.HAVIK_CLI ?? 'bun src/index.ts').split(' ')

export interface ScanFinding {
  readonly ruleId: string
  readonly severity: string
  readonly description: string
  readonly proof?: { readonly file: string; readonly line: number; readonly snippet: string }
}

export interface ScanOutput {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
  readonly findings: readonly ScanFinding[]
  readonly grade: string
  readonly json: any
}

export const scan = (path: string, ...args: string[]): Promise<ScanOutput> => scanWith({}, path, ...args)

// Like scan, with extra environment variables for the child process.
export async function scanWith(env: Record<string, string>, path: string, ...args: string[]): Promise<ScanOutput> {
  const proc = Bun.spawn([...CLI, 'scan', path, '--format', 'json', ...args], { cwd: ROOT, stdout: 'pipe', stderr: 'pipe', env: { ...process.env, ...env } })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  const code = await proc.exited
  const json = stdout.trim() ? JSON.parse(stdout) : { findings: [], score: { grade: 'none' } }
  return { code, stdout, stderr, findings: json.findings, grade: json.score.grade, json }
}

// Any havik command, from any working directory; relative parts of HAVIK_CLI are resolved against the package root.
export async function runCli(args: string[], env: Record<string, string> = {}, cwd = ROOT): Promise<{ code: number; stdout: string; stderr: string }> {
  const cli = CLI.map((part) => (existsSync(join(ROOT, part)) ? join(ROOT, part) : part))
  const proc = Bun.spawn([...cli, ...args], { cwd, stdout: 'pipe', stderr: 'pipe', env: { ...process.env, ...env } })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  return { code: await proc.exited, stdout, stderr }
}
