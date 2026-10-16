import { createHmac } from 'node:crypto'
import { isLocalHost } from '../core/exfil-patterns'
import { isPlaceholder, redactSecrets, secretMatches } from '../core/redact'
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

// A salted fingerprint lets the guard recognise a secret again without storing it.
export const fingerprint = (value: string, salt: string): string => createHmac('sha256', salt).update(value).digest('hex').slice(0, 16)

// A secret the user typed or pasted: it is now in the transcript and goes to the model with every request.
// Pasting one is a decision, so any recognised shape warns; only a placeholder is merely recorded.
export const secretsInPrompt = (prompt: string, salt: string): GuardFinding[] => {
  const matches = secretMatches(prompt.slice(0, MAX_RESPONSE_BYTES))
  if (matches.length === 0) return []
  const what = [...new Set(matches.map(m => m.kind))].join(', ')
  const fingerprints = [...new Set(matches.map(m => fingerprint(m.value, salt)))]
  const severity: Severity = matches.some(m => !isPlaceholder(m.value)) ? 'high' : 'medium'
  return [{
    detector: 'secret-in-prompt', severity, key: `secret-in-prompt:${fingerprints.join(',')}`,
    message: `${what} in your message: it is now in the session transcript and is sent to the model with every request`,
    label: `${what} you pasted`, kind: what, evidence: 'observed', fingerprints,
  }]
}

const SECRET_WORD = String.raw`(?:api[ -]?keys?|tokens?|passwords?|secrets?|credentials?|private keys?|access keys?|keys?)`
// How an agent says it saw a secret in the user's message, in a format havik may not recognise.
// General advice ("rotate keys every 90 days", "paste your key into .env") does not match.
const AGENT_NOTICED = [
  new RegExp(String.raw`\byou(?:['’]ve| have)?\s+(?:just\s+|also\s+)?(?:pasted|shared|posted|exposed|leaked|typed|included)\s+(?:\S+\s+){0,4}?${SECRET_WORD}\b`, 'i'),
  /\b(?:rotate|revoke|regenerate)\s+(?:(?:that|this|the|your)\s+)?(?:exposed|pasted|leaked|shared|compromised)\b/i,
  new RegExp(String.raw`\b(?:rotate|revoke|regenerate)\s+(?:that|this)\s+(?:[\w-]+\s+)?${SECRET_WORD}\b`, 'i'),
  new RegExp(String.raw`\b${SECRET_WORD}\s+(?:is|are|was|were)\s+now\s+(?:exposed|visible|in (?:the|this) (?:chat|conversation|transcript))`, 'i'),
]

// A reply that talks about a pasted secret may quote it, in a format redactSecrets does not know:
// any long run of letters and digits mixed is masked too.
const OPAQUE = /[A-Za-z0-9_+/=-]{16,}/g
const maskOpaque = (text: string): string => text.replace(OPAQUE, t => (/\d/.test(t) && /[A-Za-z]/.test(t) ? '[REDACTED]' : t))

export const agentNoticedSecret = (reply: string): GuardFinding[] => {
  const flat = maskOpaque(redactSecrets(reply.slice(0, MAX_RESPONSE_BYTES).replace(/\s+/g, ' ')))
  const hit = AGENT_NOTICED.map(re => re.exec(flat)).find(m => m !== null)
  if (!hit) return []
  const quote = flat.slice(Math.max(0, hit.index - 30), hit.index + 90).trim()
  return [{
    detector: 'secret-in-prompt', severity: 'high', key: 'secret-in-prompt:agent-noticed',
    message: `the agent says you shared a secret ("${quote}"): it is in the session transcript`,
    label: 'a secret the agent noticed in your message', kind: 'noticed by the agent', evidence: 'observed',
  }]
}

// `alreadyInContext` says whether the user pasted this value earlier; the paste was reported then, not the tool now.
export const secretsInResult = (source: string, response: unknown, sourceCritical: boolean, testRun = false, alreadyInContext: (value: string) => boolean = () => false): GuardFinding[] => {
  const matches = secretMatches(stringsOf(response, MAX_RESPONSE_STRINGS, MAX_RESPONSE_BYTES).join('\n')).filter(m => !alreadyInContext(m.value))
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
