import { randomBytes } from 'node:crypto'
import { claudeCode, eventsOf } from '../agents/claude-code'
import type { AgentDef } from '../agents/types'
import type { SensitivityMap } from '../core/sensitivity'
import { formatSession, summarise, type SessionSummary } from './audit'
import { tildify } from './accesses'
import { handleEvent } from './engine'
import type { GuardConfig } from './policy'
import { memoryStore } from './session'
import type { AuditLine } from './types'

export { eventsOf }

export interface ReplayOptions {
  readonly projectsDir?: string   // Claude Code's transcripts, when not in ~/.claude/projects
  readonly home: string
  readonly config: GuardConfig
  readonly map: SensitivityMap
  readonly since?: number
  readonly now?: number
  readonly scanScripts?: boolean
  readonly agents?: readonly AgentDef[]
}

// `findings` keeps the high and critical findings and every pasted secret, for the one-screen summary.
export interface ReplayResult {
  readonly sessions: number; readonly toolCalls: number; readonly days: number
  readonly summaries: SessionSummary[]; readonly findings: AuditLine[]
  readonly agents: Readonly<Record<string, { readonly sessions: number; readonly toolCalls: number; readonly unknownActions: number }>>
  readonly warnings: readonly string[]
}

// What the guard would have said about past conversations, from each agent's own records, through the same detectors.
export const replayAgents = async (o: ReplayOptions): Promise<ReplayResult> => {
  const now = o.now ?? Date.now()
  const store = memoryStore()
  const salt = randomBytes(16).toString('hex')
  const days = new Set<string>()
  const perAgent: Record<string, { sessions: number; toolCalls: number; unknownActions: number }> = {}
  const warnings: string[] = []
  let toolCalls = 0
  for (const def of o.agents ?? [claudeCode]) {
    if (!def.history) continue
    for await (const item of def.history({ home: o.home, since: o.since, now, dir: def.id === claudeCode.id ? o.projectsDir : undefined })) {
      if ('warning' in item) {
        warnings.push(`${def.name}: ${item.warning}`)
        continue
      }
      const counts = (perAgent[def.id] ??= { sessions: 0, toolCalls: 0, unknownActions: 0 })
      counts.unknownActions += Object.values(item.unknown ?? {}).reduce((n, k) => n + k, 0)
      let seen = false
      for (const { event, at } of item.events) {
        if (o.since !== undefined && now - at > o.since) continue
        seen = true
        if (event.hook_event_name === 'PreToolUse') {
          toolCalls++
          counts.toolCalls++
          days.add(new Date(at).toISOString().slice(0, 10))
        }
        await handleEvent({ ...event, agent: def.id }, {
          home: o.home, config: o.config, map: o.map, store,
          now: () => at, ms: () => 0, spent: () => 0, scanScripts: o.scanScripts ?? true, prune: false, salt,
        })
      }
      if (seen) counts.sessions++
    }
  }
  const bySession = new Map<string, AuditLine[]>()
  for (const line of store.lines) bySession.set(line.session_id, [...(bySession.get(line.session_id) ?? []), line])
  const summaries = [...bySession].map(([session, lines]) => summarise(session, lines)).sort((a, b) => a.first.localeCompare(b.first))
  // Every secret the user pasted is listed, whatever its severity; for the rest, high and critical.
  const findings = store.lines.filter(l => l.event === 'finding' && (l.detector === 'secret-in-prompt' || l.severity === 'critical' || l.severity === 'high'))
  return { sessions: bySession.size, toolCalls, days: days.size, summaries, findings, agents: perAgent, warnings }
}

// Claude Code only: `havik guard replay` and its tests.
export const replaySessions = (o: ReplayOptions): Promise<ReplayResult> => replayAgents({ ...o, agents: [claudeCode] })

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

