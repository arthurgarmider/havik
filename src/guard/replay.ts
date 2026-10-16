import { stat } from 'node:fs/promises'
import { basename, dirname } from 'node:path'
import { findFiles, readTextOrNull } from '../core/fs'
import { asArray, asRecord } from '../core/json'
import type { SensitivityMap } from '../core/sensitivity'
import { formatSession, summarise, type SessionSummary } from './audit'
import { tildify } from './accesses'
import { handleEvent } from './engine'
import type { GuardConfig } from './policy'
import { memoryStore } from './session'
import type { AuditLine, HookEvent } from './types'

// What the guard would have said about past sessions, from the transcripts Claude Code keeps in
// ~/.claude/projects. Best-effort: the transcript format is internal to Claude Code and can change.
export interface Replayed { readonly event: HookEvent; readonly at: number }

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

export const eventsOf = (text: string): Replayed[] => {
  const out: Replayed[] = []
  const calls = new Map<string, { name: string; input: unknown }>()
  let mode: string | undefined
  for (const raw of text.split('\n')) {
    let line: Record<string, any>
    try {
      line = asRecord(JSON.parse(raw))
    } catch {
      continue
    }
    const session_id = str(line['sessionId'])
    const cwd = str(line['cwd'])
    mode = str(line['permissionMode']) ?? mode
    if (!session_id || !cwd) continue
    const at = Date.parse(str(line['timestamp']) ?? '') || 0
    const base = { session_id, cwd, permission_mode: mode }
    for (const block of asArray(asRecord(line['message'])['content'])) {
      const b = asRecord(block)
      if (line['type'] === 'assistant' && b['type'] === 'tool_use' && typeof b['id'] === 'string' && typeof b['name'] === 'string') {
        calls.set(b['id'], { name: b['name'], input: b['input'] })
        out.push({ at, event: { ...base, hook_event_name: 'PreToolUse', tool_name: b['name'], tool_input: b['input'], tool_use_id: b['id'] } })
      }
      if (line['type'] === 'user' && b['type'] === 'tool_result' && typeof b['tool_use_id'] === 'string') {
        const call = calls.get(b['tool_use_id'])
        if (!call || b['is_error'] === true) continue
        const response = line['toolUseResult'] ?? b['content']
        out.push({ at, event: { ...base, hook_event_name: 'PostToolUse', tool_name: call.name, tool_input: call.input, tool_use_id: b['tool_use_id'], tool_response: response } })
      }
    }
  }
  return out
}

export interface ReplayOptions {
  readonly projectsDir: string
  readonly home: string
  readonly config: GuardConfig
  readonly map: SensitivityMap
  readonly since?: number
  readonly now?: number
  readonly scanScripts?: boolean
}

// `findings` keeps the high and critical findings, for the one-screen summary.
export interface ReplayResult { readonly sessions: number; readonly toolCalls: number; readonly days: number; readonly summaries: SessionSummary[]; readonly findings: AuditLine[] }

// A subagent's transcript lives under <session>/subagents/, and belongs to that session.
const sessionOf = (file: string): string =>
  basename(dirname(file)) === 'subagents' ? basename(dirname(dirname(file))) : basename(file, '.jsonl')

export const replaySessions = async (o: ReplayOptions): Promise<ReplayResult> => {
  const now = o.now ?? Date.now()
  const groups = new Map<string, string[]>()
  for (const file of await findFiles('**/*.jsonl', o.projectsDir, { absolute: true, dot: true, deep: 5 })) {
    const info = await stat(file).catch(() => null)
    if (!info || (o.since !== undefined && now - info.mtimeMs > o.since)) continue
    groups.set(sessionOf(file), [...(groups.get(sessionOf(file)) ?? []), file])
  }
  const store = memoryStore()
  const days = new Set<string>()
  let toolCalls = 0
  // One session at a time, so memory holds a single session's events.
  for (const files of groups.values()) {
    const events: Replayed[] = []
    for (const file of files) events.push(...eventsOf((await readTextOrNull(file)) ?? ''))
    events.sort((a, b) => a.at - b.at)
    for (const { event, at } of events) {
      if (o.since !== undefined && now - at > o.since) continue
      if (event.hook_event_name === 'PreToolUse') {
        toolCalls++
        days.add(new Date(at).toISOString().slice(0, 10))
      }
      await handleEvent(event, {
        home: o.home, config: o.config, map: o.map, store,
        now: () => at, ms: () => 0, spent: () => 0, scanScripts: o.scanScripts ?? true, prune: false,
      })
    }
  }
  const bySession = new Map<string, AuditLine[]>()
  for (const line of store.lines) bySession.set(line.session_id, [...(bySession.get(line.session_id) ?? []), line])
  const summaries = [...bySession].map(([session, lines]) => summarise(session, lines)).sort((a, b) => a.first.localeCompare(b.first))
  const findings = store.lines.filter(l => l.event === 'finding' && (l.severity === 'critical' || l.severity === 'high'))
  return { sessions: bySession.size, toolCalls, days: days.size, summaries, findings }
}

// The report a person reads after one command: totals, the warning rate per active day, then every session that would have warned.
export const formatReplay = (r: ReplayResult, dir: string, span: string, home: string, all = false): string => {
  const warned = r.summaries.filter(s => s.alerts > 0)
  const total = (k: 'critical' | 'high' | 'medium') => r.summaries.reduce((n, s) => n + s.counts[k], 0)
  const alerts = r.summaries.reduce((n, s) => n + s.alerts, 0)
  const detectors = new Map<string, number>()
  for (const s of r.summaries) for (const [d, n] of Object.entries(s.byDetector)) detectors.set(d, (detectors.get(d) ?? 0) + (n ?? 0))
  const perDay = r.days > 0 ? (alerts / r.days).toFixed(1) : '0'
  const shown = all ? r.summaries : warned
  return [
    `havik guard replay: ${r.sessions} sessions, ${r.toolCalls} tool calls on ${r.days} days in the last ${span} (${tildify(dir, home)})`,
    'Best-effort: built from the transcripts Claude Code keeps, whose format can change; scripts were scanned as they are now.',
    '',
    `It would have warned ${alerts} times in ${warned.length} sessions (${total('critical')} critical, ${total('high')} high): ${perDay} a day. ${total('medium')} medium findings would have been recorded without a warning.`,
    ...(detectors.size > 0 ? [`by detector: ${[...detectors].map(([d, n]) => `${d} ${n}`).join(' · ')}`] : []),
    ...shown.map(s => `\n${formatSession(s, home)}`),
  ].join('\n')
}

