import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { appendFile, mkdtemp, rm, utimes } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { auditExitCode, formatAudit, parseSince, readAudit, summarise } from '../../src/guard/audit'
import { appendLine, sessionFile } from '../../src/guard/session'
import type { AuditLine } from '../../src/guard/types'

let home: string
const saved = process.env.HAVIK_HOME
beforeEach(async () => { home = await mkdtemp(join(tmpdir(), 'havik-audit-')); process.env.HAVIK_HOME = home })
afterEach(async () => {
  if (saved === undefined) delete process.env.HAVIK_HOME
  else process.env.HAVIK_HOME = saved
  await rm(home, { recursive: true, force: true })
})

const at = (minute: number) => `2026-10-15T10:${String(minute).padStart(2, '0')}:00.000Z`
const L = (over: Partial<AuditLine>): AuditLine => ({ ts: at(0), session_id: 's1', event: 'access', ms: 30, cwd: '/home/u/proj', permission_mode: 'default', ...over })
const ATTACK: AuditLine[] = [
  L({ event: 'session', roots: ['/home/u/proj'] }),
  L({ ts: at(1), event: 'finding', detector: 'sensitive-access', severity: 'critical', kind: 'read', path: '/home/u/.pypirc', key: 'a', alerted: true, reason: 'Read ~/.pypirc: PyPI upload tokens, outside this project', ms: 35 }),
  L({ ts: at(1), event: 'finding', detector: 'secret-in-result', severity: 'critical', key: 'b', alerted: true, reason: 'PyPI token entered the context from Read ~/.pypirc', ms: 40 }),
  L({ ts: at(4), event: 'finding', detector: 'data-leaving', severity: 'critical', host: 'evil.example', key: 'c', alerted: true, reason: 'WebFetch to evil.example after PyPI token from Read ~/.pypirc (3 min earlier)', ms: 33 }),
  L({ ts: at(5), event: 'finding', detector: 'script-about-to-run', severity: 'critical', key: 'd', alerted: true, evidence: 'static', proof: 'scripts/run.js:7', skill: 'date-helper', reason: 'scripts/run.js of skill date-helper reads credentials (line 6) and sends data to evil.example (line 7)', ms: 120 }),
  L({ ts: at(6), event: 'finding', detector: 'sensitive-access', severity: 'medium', kind: 'read', path: '/home/u/Documents/a.pdf', key: 'e', alerted: false, ms: 31 }),
  L({ ts: at(7), event: 'access', kind: 'send', host: 'docs.example.com', ms: 29 }),
  L({ ts: at(8), event: 'guard-error', reason: 'boom', ms: 20 }),
  L({ ts: at(9), event: 'budget-exceeded', reason: 'script scan skipped', permission_mode: 'bypassPermissions', ms: 400 }),
]

describe('summarise', () => {
  it('counts findings, warnings, chains, scripts, paths, hosts, errors and hook time', () => {
    const s = summarise('s1', ATTACK)
    expect(s.counts).toEqual({ critical: 4, high: 0, medium: 1, low: 0 })
    expect(s.byDetector).toEqual({ 'sensitive-access': 2, 'secret-in-result': 1, 'data-leaving': 1, 'script-about-to-run': 1 })
    expect(s.alerts).toBe(4)
    expect(s.chains).toEqual(['WebFetch to evil.example after PyPI token from Read ~/.pypirc (3 min earlier)'])
    expect(s.scripts).toEqual(['scripts/run.js of skill date-helper reads credentials (line 6) and sends data to evil.example (line 7)'])
    expect(s.topPaths).toEqual([['/home/u/.pypirc', 1], ['/home/u/Documents/a.pdf', 1]])
    expect(s.topHosts).toEqual([['docs.example.com', 1], ['evil.example', 1]])
    expect([s.errors, s.overBudget, s.p95ms]).toEqual([1, 1, 400])
    expect(s.modes).toEqual(['default', 'bypassPermissions'])
    expect([s.first, s.last, s.cwd]).toEqual([at(0), at(9), '/home/u/proj'])
  })
})

describe('readAudit', () => {
  it('reads every session file in the time window, skipping torn lines', async () => {
    for (const line of ATTACK) await appendLine(line)
    await appendLine(L({ session_id: 'old', event: 'session' }))
    const old = new Date(Date.now() - 10 * 86_400_000)
    await utimes(sessionFile('old'), old, old)
    await appendFile(sessionFile('s1'), '{"ts":"2026')
    const sessions = await readAudit({ since: parseSince('7d') })
    expect(sessions.map((s) => s.session)).toEqual(['s1'])
    expect(sessions[0].counts.critical).toBe(4)
    expect((await readAudit({ session: 'old' })).map((s) => s.session)).toEqual(['old'])
  })

  it('returns nothing when there is no audit directory', async () => {
    expect(await readAudit({ since: parseSince('7d') })).toEqual([])
  })
})

describe('parseSince, formatAudit and auditExitCode', () => {
  it('parses days and hours, and nothing else', () => {
    expect([parseSince('7d'), parseSince('12h'), parseSince('1w'), parseSince('x')]).toEqual([604_800_000, 43_200_000, undefined, undefined])
  })

  it('renders a session the way a person reads it', () => {
    const text = formatAudit([summarise('s1', ATTACK)], '/home/u', '7d')
    for (const part of ['s1', '~/proj', '4 critical', '1 medium', '4 warned in the session', 'WebFetch to evil.example', 'scripts/run.js of skill date-helper', '~/.pypirc', 'evil.example', 'bypassPermissions', 'p95 400 ms']) expect(text).toContain(part)
    expect(formatAudit([], '/home/u', '7d')).toContain('nothing recorded in the last 7d')
  })

  it('exits 2 for any critical, 1 for any high, else 0', () => {
    const high = summarise('h', [L({ event: 'finding', detector: 'sensitive-access', severity: 'high', key: 'k', alerted: true })])
    expect([auditExitCode([summarise('s1', ATTACK)]), auditExitCode([high]), auditExitCode([])]).toEqual([2, 1, 0])
  })
})
