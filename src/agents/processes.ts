import { execFile } from 'node:child_process'
import { basename } from 'node:path'
import type { Result } from '../core/types'

// One running program. Only names are kept: the command lines of tool servers carry tokens, so every argument is dropped here.
export interface Proc { readonly pid: number; readonly ppid: number; readonly exe: string; readonly script?: string; readonly pkg?: string }

const RUNNER = /^(?:node|bun|deno|python(?:\d+(?:\.\d+)?)?|ruby|uv|uvx)$/
const INLINE = new Set(['-e', '-c', '-p', '--eval', '--print'])
const NAME = /^[\w@./-]{1,200}$/
const COMM_LINE = /^\s*(\d+)\s+(\d+)\s+(.+)$/
const ARGS_LINE = /^\s*(\d+)\s+(.+)$/
const PACKAGE = /node_modules\/((?:@[\w.-]+\/)?[\w.-]+)\//

// The script or module a runner runs (`node …/index.js`, `python -m hermes_cli.main`), and the npm package it lives in.
const scriptOf = (exe: string, args: string): { script?: string; pkg?: string } => {
  if (!RUNNER.test(exe)) return {}
  const tokens = args.trim().split(/\s+/)
  const start = tokens.findIndex(t => basename(t) === exe)
  if (start < 0) return {}
  const rest = tokens.slice(start + 1)
  if (rest.some(t => INLINE.has(t))) return {}
  const module = rest.indexOf('-m')
  const target = module >= 0 ? rest[module + 1] : rest.find(t => !t.startsWith('-'))
  if (!target || !NAME.test(target)) return {}
  return { script: module >= 0 ? target : basename(target), pkg: PACKAGE.exec(target)?.[1] }
}

export const parsePs = (commText: string, argsText: string): Proc[] => {
  const args = new Map<number, string>()
  for (const line of argsText.split('\n')) {
    const m = ARGS_LINE.exec(line)
    if (m) args.set(Number(m[1]), m[2])
  }
  return commText.split('\n').flatMap((line): Proc[] => {
    const m = COMM_LINE.exec(line)
    if (!m) return []
    const exe = basename(m[3].trim())
    return [{ pid: Number(m[1]), ppid: Number(m[2]), exe, ...scriptOf(exe, args.get(Number(m[1])) ?? '') }]
  })
}

const ps = (args: readonly string[]): Promise<string> =>
  new Promise((resolve, reject) => execFile('ps', args, { timeout: 3_000, maxBuffer: 32 * 1024 * 1024 }, (error, stdout) => (error ? reject(error) : resolve(stdout))))

export const listProcesses = async (platform: string = process.platform): Promise<Result<Proc[]>> => {
  if (platform === 'win32') return { ok: false, error: 'running programs are not checked on Windows yet' }
  try {
    const [comm, args] = await Promise.all([ps(['-axo', 'pid=,ppid=,comm=']), ps(['-axww', '-o', 'pid=,args='])])
    return { ok: true, value: parsePs(comm, args) }
  } catch (e) {
    return { ok: false, error: `could not list running programs: ${e instanceof Error ? e.message : String(e)}` }
  }
}
