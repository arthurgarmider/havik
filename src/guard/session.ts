import { appendFile, mkdir, readdir, stat, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { readTextOrNull } from '../core/fs'
import { havikHome } from './policy'
import type { AuditLine, Memory } from './types'

const MAX_LINE = 4000
const DAY_MS = 86_400_000

export const auditDir = (): string => join(havikHome(), 'audit')
export const sessionFile = (sessionId: string): string =>
  join(auditDir(), `${sessionId.replace(/[^\w.-]/g, '_').slice(0, 100) || 'unknown'}.jsonl`)

const fit = (line: AuditLine): string => {
  const text = JSON.stringify(line)
  if (text.length <= MAX_LINE) return text
  const shrunk = JSON.stringify({ ...line, snippet: undefined, chain: undefined, roots: line.roots?.slice(0, 5), path: line.path?.slice(0, 500), reason: line.reason?.slice(0, 200), label: line.label?.slice(0, 200) })
  if (shrunk.length <= MAX_LINE) return shrunk
  return JSON.stringify({ ts: line.ts, session_id: line.session_id.slice(0, 100), event: 'guard-error', reason: 'audit line too long', ms: line.ms })
}

// One write per line, each under 4 KB, so hooks running in parallel cannot interleave inside a line.
export const appendLine = async (line: AuditLine): Promise<void> => {
  await mkdir(auditDir(), { recursive: true, mode: 0o700 })
  await appendFile(sessionFile(line.session_id), `${fit(line)}\n`, { mode: 0o600 })
}

// The same rule as detectors.ARMS: a secret in a result, or a sensitive read, at high or above.
const ARMS = (line: AuditLine): boolean =>
  (line.detector === 'secret-in-result' || (line.detector === 'sensitive-access' && line.kind === 'read')) && (line.severity === 'critical' || line.severity === 'high')

export const emptyMemory = (): Memory => ({ started: false, roots: [], remoteMcp: {}, armed: [], alerted: new Set() })

// What one audit line adds to the session memory. Access lines add nothing.
export const applyLine = (memory: Memory, line: AuditLine): Memory => {
  if (line.event === 'session') {
    return { ...memory, started: true, roots: [...memory.roots, ...(line.roots ?? [])], remoteMcp: { ...memory.remoteMcp, ...(line.remote_mcp ?? {}) } }
  }
  if (line.event !== 'finding') return memory
  const alerted = line.alerted && line.key ? new Set([...memory.alerted, line.key]) : memory.alerted
  const armed = ARMS(line)
    ? [...memory.armed, { ts: line.ts, label: line.label ?? line.path ?? 'a sensitive read', severity: line.severity ?? 'high', tool_use_id: line.tool_use_id }]
    : memory.armed
  return { ...memory, alerted, armed }
}

export const readMemory = async (sessionId: string): Promise<Memory> => {
  const text = (await readTextOrNull(sessionFile(sessionId))) ?? ''
  let memory = emptyMemory()
  for (const raw of text.split('\n')) {
    // Access lines are most of the file and never matter here, so they are skipped before parsing.
    if (!raw || raw.includes('"event":"access"')) continue
    try {
      memory = applyLine(memory, JSON.parse(raw))
    } catch {
      // a torn or foreign line teaches nothing
    }
  }
  return memory
}

// Where the guard keeps its memory and audit: files for the hook, memory for a replay of past sessions.
export interface Store {
  readMemory(sessionId: string): Promise<Memory>
  append(line: AuditLine): Promise<void>
}

export const diskStore: Store = { readMemory, append: appendLine }

export const memoryStore = (): Store & { readonly lines: AuditLine[] } => {
  const lines: AuditLine[] = []
  const memories = new Map<string, Memory>()
  return {
    lines,
    readMemory: async (sessionId) => memories.get(sessionId) ?? emptyMemory(),
    append: async (line) => {
      lines.push(line)
      memories.set(line.session_id, applyLine(memories.get(line.session_id) ?? emptyMemory(), line))
    },
  }
}

export const pruneAudit = async (days: number, now = Date.now()): Promise<number> => {
  let names: string[]
  try {
    names = await readdir(auditDir())
  } catch {
    return 0
  }
  let removed = 0
  for (const name of names.filter(n => n.endsWith('.jsonl'))) {
    const path = join(auditDir(), name)
    const info = await stat(path).catch(() => null)
    if (!info || now - info.mtimeMs <= days * DAY_MS) continue
    await unlink(path).catch(() => undefined)
    removed++
  }
  return removed
}
