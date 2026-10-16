import { readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { readTextOrNull } from '../core/fs'
import type { Severity } from '../core/types'
import { tildify } from './accesses'
import { auditDir } from './session'
import type { AuditLine, Detector } from './types'

export interface SessionSummary {
  readonly session: string
  readonly first: string
  readonly last: string
  readonly cwd: string
  readonly modes: readonly string[]
  readonly counts: Readonly<Record<Severity, number>>
  readonly byDetector: Readonly<Partial<Record<Detector, number>>>
  readonly alerts: number
  readonly chains: readonly string[]
  readonly scripts: readonly string[]
  readonly topPaths: ReadonlyArray<readonly [string, number]>
  readonly topHosts: ReadonlyArray<readonly [string, number]>
  readonly errors: number
  readonly overBudget: number
  readonly p95ms: number
}

const SPAN = /^(\d{1,4})([dh])$/
const RISKY_MODES = new Set(['bypassPermissions', 'auto'])

export const parseSince = (text: string): number | undefined => {
  const m = SPAN.exec(text.trim())
  return m ? Number(m[1]) * (m[2] === 'd' ? 86_400_000 : 3_600_000) : undefined
}

const parseLines = (text: string): AuditLine[] =>
  text.split('\n').flatMap((raw): AuditLine[] => {
    if (!raw) return []
    try {
      return [JSON.parse(raw) as AuditLine]
    } catch {
      return []
    }
  })

const unique = <T>(values: readonly T[]): T[] => [...new Set(values)]

const top = (values: readonly string[], n = 5): Array<[string, number]> => {
  const counts = new Map<string, number>()
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1)
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n)
}

const p95 = (values: readonly number[]): number => {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))]
}

export const summarise = (session: string, lines: readonly AuditLine[]): SessionSummary => {
  const findings = lines.filter(l => l.event === 'finding')
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  const byDetector: Partial<Record<Detector, number>> = {}
  for (const f of findings) {
    if (f.severity) counts[f.severity]++
    if (f.detector) byDetector[f.detector] = (byDetector[f.detector] ?? 0) + 1
  }
  const reasons = (detector: Detector) => unique(findings.filter(f => f.detector === detector && f.reason).map(f => f.reason ?? ''))
  return {
    session,
    first: lines[0]?.ts ?? '',
    last: lines[lines.length - 1]?.ts ?? '',
    cwd: lines.find(l => l.cwd)?.cwd ?? '',
    modes: unique(lines.flatMap(l => (l.permission_mode ? [l.permission_mode] : []))),
    counts,
    byDetector,
    alerts: findings.filter(f => f.alerted).length,
    chains: reasons('data-leaving'),
    scripts: reasons('script-about-to-run'),
    topPaths: top(findings.flatMap(f => (f.path ? [f.path] : []))),
    topHosts: top(lines.flatMap(l => (l.host ? [l.host] : []))),
    errors: lines.filter(l => l.event === 'guard-error').length,
    overBudget: lines.filter(l => l.event === 'budget-exceeded').length,
    p95ms: p95(lines.map(l => l.ms).filter(ms => typeof ms === 'number')),
  }
}

export const readAudit = async (opts: { since?: number; session?: string; now?: number } = {}): Promise<SessionSummary[]> => {
  const now = opts.now ?? Date.now()
  let names: string[]
  try {
    names = await readdir(auditDir())
  } catch {
    return []
  }
  const wanted = opts.session?.replace(/[^\w.-]/g, '_')
  const sessions: SessionSummary[] = []
  for (const name of names.filter(n => n.endsWith('.jsonl'))) {
    const session = name.slice(0, -'.jsonl'.length)
    if (wanted && session !== wanted) continue
    const path = join(auditDir(), name)
    const info = await stat(path).catch(() => null)
    if (!info || (opts.since !== undefined && now - info.mtimeMs > opts.since)) continue
    const lines = parseLines((await readTextOrNull(path)) ?? '')
    if (lines.length > 0) sessions.push(summarise(session, lines))
  }
  return sessions.sort((a, b) => a.first.localeCompare(b.first))
}

const pairs = (list: ReadonlyArray<readonly [string, number]>, home: string): string =>
  list.map(([v, n]) => `${tildify(v, home)} (${n})`).join(', ') || 'none'

export const formatSession = (s: SessionSummary, home: string): string => {
  const severities = (['critical', 'high', 'medium'] as const).filter(k => s.counts[k] > 0).map(k => `${s.counts[k]} ${k}`).join(', ') || 'none'
  const risky = s.modes.filter(m => RISKY_MODES.has(m))
  return [
    `${s.session}  ${s.first.slice(0, 16).replace('T', ' ')} → ${s.last.slice(11, 16)}  ${tildify(s.cwd, home)}  modes: ${s.modes.join(', ') || 'unknown'}`,
    `  findings: ${severities} (${s.alerts} warned in the session)`,
    ...(Object.keys(s.byDetector).length > 0 ? [`  ${Object.entries(s.byDetector).map(([d, n]) => `${d} ${n}`).join(' · ')}`] : []),
    ...s.chains.map(c => `  leaving: ${c}`),
    ...s.scripts.map(c => `  script: ${c}`),
    `  top paths: ${pairs(s.topPaths, home)}`,
    `  top hosts: ${pairs(s.topHosts, home)}`,
    ...(risky.length > 0 ? [`  note: ran in ${risky.join(', ')}, where the agent could have edited the guard's settings`] : []),
    `  hook p95 ${s.p95ms} ms · errors ${s.errors} · over budget ${s.overBudget}`,
  ].join('\n')
}

export const formatAudit = (sessions: readonly SessionSummary[], home: string, span: string): string =>
  sessions.length === 0
    ? `havik audit: nothing recorded in the last ${span} (is the guard installed? havik guard status)`
    : [`havik audit: ${sessions.length} session${sessions.length === 1 ? '' : 's'} in the last ${span}`, ...sessions.map(s => formatSession(s, home))].join('\n\n')

export const auditExitCode = (sessions: readonly SessionSummary[]): 0 | 1 | 2 =>
  sessions.some(s => s.counts.critical > 0) ? 2 : sessions.some(s => s.counts.high > 0) ? 1 : 0
