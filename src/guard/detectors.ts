import { isLocalHost } from '../core/exfil-patterns'
import { isPlaceholder, secretMatches } from '../core/redact'
import type { Severity } from '../core/types'
import { stringsOf, tildify } from './accesses'
import { judgePath, type PolicyContext } from './policy'
import type { Access, Armed, GuardFinding } from './types'

const MAX_RESPONSE_BYTES = 256_000
const MAX_RESPONSE_STRINGS = 5_000
const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 }
// A sensitive read arms data-leaving for this long; a send an hour later is not the same story.
const ARMED_WINDOW_MS = 20 * 60_000
// Shapes that ordinary output shows all day (local database URLs, example headers); a token with a vendor prefix is not one of them.
const WEAK_KINDS = new Set(['Bearer token', 'password in a URL', 'credential in a URL parameter', 'JWT'])

export const atLeast = (severity: Severity, floor: Severity): boolean => RANK[severity] >= RANK[floor]

export interface DetectContext extends PolicyContext {
  readonly armed: readonly Armed[]
  readonly now: number
}

// Shell startup files matter when written (persistence); reading one is how an agent debugs PATH.
const RC_FILE = /^~\/\.(?:zshrc|bashrc|bash_profile|profile|zprofile|gitconfig)$/

const labelOf = (a: Access, home: string): string => `${a.via} ${a.path ? tildify(a.path, home) : a.host ?? ''}`.trim()

export const sensitiveAccesses = (list: readonly Access[], ctx: DetectContext): GuardFinding[] =>
  list.flatMap((a): GuardFinding[] => {
    if ((a.kind !== 'read' && a.kind !== 'use' && a.kind !== 'write') || !a.path) return []
    const verdict = judgePath(a.path, ctx)
    if (verdict.authorized || !atLeast(verdict.level, 'medium')) return []
    const label = labelOf(a, ctx.home)
    // A key ssh uses never reaches the context; it is recorded, not warned about.
    const severity = a.kind === 'use' || (a.kind === 'read' && RC_FILE.test(tildify(a.path, ctx.home))) ? 'medium' : verdict.level
    return [{
      detector: 'sensitive-access', severity, key: `sensitive-access:${a.kind}:${a.path}`,
      message: `${label}: ${verdict.reason}, ${a.kind === 'use' ? 'used as a key' : 'outside this project'}`, label, kind: a.kind, path: a.path, evidence: 'observed',
    }]
  })

// A recognised credential in what the tool returned: from now on it is in the transcript and every later request.
// Test suites print their fixture tokens; a token in a test run's output is noted, not treated as a live secret.
const TEST_RUN = /(?:^|[\s;&|])(?:(?:bun|npm|pnpm|yarn|npx)\s+(?:run\s+)?(?:test\b|vitest\b|jest\b)|pytest\b|go\s+test\b|cargo\s+test\b|jest\b|vitest\b)/
export const isTestRun = (command: string): boolean => TEST_RUN.test(command)

export const secretsInResult = (source: string, response: unknown, sourceCritical: boolean, testRun = false): GuardFinding[] => {
  const matches = secretMatches(stringsOf(response, MAX_RESPONSE_STRINGS, MAX_RESPONSE_BYTES).join('\n'))
  if (matches.length === 0) return []
  const kinds = [...new Set(matches.map(m => m.kind))]
  const what = kinds.join(', ')
  // Only a token that is neither weak-shaped nor a placeholder counts as a live secret.
  const live = matches.some(m => !WEAK_KINDS.has(m.kind) && !isPlaceholder(m.value))
  const severity: Severity = sourceCritical ? 'critical' : testRun || !live ? 'medium' : 'high'
  return [{
    detector: 'secret-in-result', severity, key: `secret-in-result:${source}`,
    message: `${what} entered the context from ${source}`, label: `${what} from ${source}`, kind: kinds.join(', '), evidence: 'observed',
  }]
}

const ARMS = (f: GuardFinding): boolean =>
  (f.detector === 'secret-in-result' || (f.detector === 'sensitive-access' && f.kind === 'read')) && atLeast(f.severity, 'high')

const earlier = (ms: number): string =>
  ms < 5_000 ? '' : ms < 120_000 ? ` (${Math.round(ms / 1000)} s earlier)` : ` (${Math.round(ms / 60_000)} min earlier)`

// A send to an outside host after something sensitive was read or entered the context, earlier or in this same call.
export const dataLeaving = (list: readonly Access[], current: readonly GuardFinding[], ctx: DetectContext): GuardFinding[] => {
  const nowIso = new Date(ctx.now).toISOString()
  const sameCall = current.filter(ARMS).map(f => ({ ts: nowIso, label: f.label, severity: f.severity }))
  const recent = ctx.armed.filter(a => ctx.now - Date.parse(a.ts) <= ARMED_WINDOW_MS)
  const armed: Armed[] = [...recent, ...sameCall]
  if (armed.length === 0) return []
  const latest = armed[armed.length - 1]
  // Read and send in one command is the exfiltration itself; a send some calls later is a correlation.
  const severity: Severity = sameCall.some(a => a.severity === 'critical') ? 'critical' : 'high'
  const chain = armed.slice(-5).flatMap(a => (a.tool_use_id ? [a.tool_use_id] : []))
  return list
    .filter(a => a.kind === 'send' && a.host && !isLocalHost(a.host))
    .map((a): GuardFinding => ({
      detector: 'data-leaving', severity, key: `data-leaving:${a.host}`,
      message: `${a.via} to ${a.host} after ${latest.label}${earlier(ctx.now - Date.parse(latest.ts))}`,
      label: `${a.via} to ${a.host}`, kind: 'send', host: a.host, evidence: 'observed', chain,
    }))
}

// Every call to a remote MCP server's tool sends its arguments to that server.
export const mcpServerSends = (toolName: string, remoteMcp: Readonly<Record<string, string>>): Access[] => {
  const server = toolName.startsWith('mcp__') ? toolName.split('__')[1] : undefined
  const host = server ? remoteMcp[server] : undefined
  return host ? [{ kind: 'send', host, via: toolName }] : []
}
