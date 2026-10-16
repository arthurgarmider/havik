import { redactSecrets } from '../core/redact'
import type { Access, AuditLine, GuardFinding, HookEvent } from './types'

const MAX_MESSAGE = 300
const MAX_SYSTEM_MESSAGE = 1000

// Every string that leaves the hook goes through here: redacted, one line, bounded. Redaction comes last.
export const clean = (text: string, max: number): string =>
  redactSecrets(text.slice(0, max + 500)).replace(/\p{Cc}/gu, ' ').slice(0, max)

export const baseLine = (event: HookEvent, ms: number, at = Date.now()) => ({
  ts: new Date(at).toISOString(),
  session_id: event.session_id.slice(0, 200),
  cwd: event.cwd,
  permission_mode: event.permission_mode,
  agent_type: event.agent_type,
  tool_use_id: event.tool_use_id,
  tool_name: event.tool_name,
  ms,
})

export const findingLine = (event: HookEvent, f: GuardFinding, alerted: boolean, ms: number, at?: number): AuditLine => ({
  ...baseLine(event, ms, at),
  event: 'finding',
  detector: f.detector,
  severity: f.severity,
  key: clean(f.key, 500),
  kind: f.kind,
  path: f.path && clean(f.path, 1000),
  host: f.host && clean(f.host, 300),
  script: f.script && clean(f.script, 1000),
  skill: f.skill,
  reason: clean(f.message, MAX_MESSAGE),
  label: clean(f.label, 200),
  evidence: f.evidence,
  proof: f.proof,
  chain: f.chain,
  alerted,
})

export const accessLine = (event: HookEvent, a: Access, ms: number, at?: number): AuditLine => ({
  ...baseLine(event, ms, at),
  event: a.kind === 'inline-code' ? 'inline-code' : 'access',
  kind: a.kind,
  path: a.path && clean(a.path, 1000),
  host: a.host && clean(a.host, 300),
  snippet: clean(a.via, 200),
})

// One user-visible line for everything this call found; at most three findings spelled out.
export const systemMessage = (alerts: readonly GuardFinding[]): string => {
  if (alerts.length === 0) return ''
  const parts = alerts.slice(0, 3).map(f => `${clean(f.message, MAX_MESSAGE)} (${f.severity}${f.evidence === 'static' ? ', static' : ''})`)
  const more = alerts.length > 3 ? `; and ${alerts.length - 3} more (havik audit)` : ''
  return JSON.stringify({ systemMessage: clean(`havik: ${parts.join('; ')}${more}`, MAX_SYSTEM_MESSAGE) })
}
