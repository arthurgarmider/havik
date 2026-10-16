import { describe, it, expect } from 'bun:test'
import { formatTouched } from '../../src/guard/touched'
import type { ReplayResult } from '../../src/guard/replay'
import type { AuditLine } from '../../src/guard/types'

const HOME = '/home/u'
const line = (over: Partial<AuditLine>): AuditLine => ({ ts: '2026-09-21T10:00:00.000Z', session_id: 's', event: 'finding', cwd: '/home/u/proj', severity: 'high', alerted: true, ms: 0, ...over })
const result = (findings: AuditLine[]): ReplayResult => ({ sessions: 25, toolCalls: 54318, days: 19, summaries: [], findings, agents: { 'claude-code': { sessions: 1, toolCalls: 1, unknownActions: 0 }, cursor: { sessions: 1, toolCalls: 1, unknownActions: 0 } }, warnings: [] })

const FINDINGS = [
  line({ detector: 'sensitive-access', severity: 'critical', kind: 'read', path: '/home/u/.aws/credentials', reason: 'grep ~/.aws/credentials: AWS credentials, outside this project' }),
  line({ detector: 'sensitive-access', kind: 'read', path: '/home/u/.aws/credentials' }),
  line({ detector: 'sensitive-access', kind: 'read', path: '/home/u/other/.env' }),
  line({ detector: 'sensitive-access', kind: 'write', path: '/home/u/.zshrc' }),
  line({ detector: 'sensitive-access', kind: 'read', path: '/home/u/.npmrc' }),
  line({ detector: 'secret-in-result', kind: 'Google API key, GitHub token' }),
  line({ detector: 'secret-in-result', kind: 'GitHub token' }),
  line({ detector: 'data-leaving', label: 'curl to api.example.com', host: 'api.example.com' }),
  line({ detector: 'secret-in-prompt', kind: 'password in a URL' }),
  line({ detector: 'script-about-to-run', reason: 'setup.sh downloads code and runs it (line 71)', alerted: false }),
]

describe('formatTouched', () => {
  const out = formatTouched(result(FINDINGS), '30d', HOME)

  it('opens with what was read and promises nothing left the machine', () => {
    expect(out.split('\n')[0]).toBe('havik: what Claude Code touched in the last 30d')
    expect(out).toContain('25 sessions · 54,318 tool calls · 19 active days · read on this machine, nothing sent')
  })

  it('counts distinct things per row and names at most three', () => {
    expect(out).toMatch(/sensitive files touched\s+4\s+~\/\.aws\/credentials, ~\/other\/\.env, ~\/\.zshrc \(\+1\)/)
    expect(out).toMatch(/secrets tools pulled in\s+2\s+Google API key, GitHub token/)
    expect(out).toMatch(/secrets you pasted\s+1\s+password in a URL/)
    expect(out).toMatch(/sent out right after\s+1\s+curl to api\.example\.com/)
    expect(out).toMatch(/risky scripts\s+1\s+setup\.sh downloads code and runs it/)
  })

  it('tells the story of each critical finding with its date and project', () => {
    expect(out).toMatch(/2026-09-21\s+grep ~\/\.aws\/credentials: AWS credentials, outside this project\s+in proj/)
  })

  it('ends with the warning rate and the two next commands, on one screen', () => {
    expect(out).toContain('9 warnings in 19 days (0.5 a day) would have reached the session.')
    expect(out).toContain('npx agent-havik guard install')
    expect(out).toContain('npx agent-havik guard replay')
    expect(out.split('\n').length).toBeLessThanOrEqual(24)
  })

  it('says so plainly when nothing sensitive was touched', () => {
    const clean = formatTouched(result([]), '30d', HOME)
    expect(clean).toContain('Nothing sensitive: no credential file, secret or send-after-read in 54,318 tool calls.')
    expect(clean).not.toContain('warnings in')
    expect(clean).toContain('npx agent-havik guard install')
  })
})

describe('formatTouched without transcripts', () => {
  it('says where it looked instead of reporting a clean result', () => {
    const none = formatTouched({ sessions: 0, toolCalls: 0, days: 0, summaries: [], findings: [], agents: {}, warnings: [] }, '30d', HOME, '/home/u/.claude/projects')
    expect(none).toContain('No Claude Code sessions in the last 30d under ~/.claude/projects.')
    expect(none).not.toContain('Nothing sensitive')
  })
})

describe('formatTouched width', () => {
  it('keeps every line within 100 characters and names a project by its folder', () => {
    const deep = '/home/u/git/startup/analyzer/.claude/worktrees/a-very-long-worktree-name-0123456789'
    const long = Array.from({ length: 6 }, (_, i) => line({ detector: 'sensitive-access', severity: 'critical', kind: 'read', cwd: deep, path: `/home/u/git/some/deeply/nested/folder/number-${i}/.env`, reason: `Read ~/git/some/deeply/nested/folder/number-${i}/.env: secrets file, outside this project` }))
    const out = formatTouched(result(long), '30d', HOME)
    expect(out.split('\n').filter((l) => l.length > 100)).toEqual([])
    expect(out).toContain('in a-very-long-worktree-name-0123456789')
  })
})

describe('formatTouched across agents', () => {
  const names = (id: string) => ({ 'claude-code': 'Claude Code', cursor: 'Cursor' } as Record<string, string>)[id] ?? id
  const many = [
    line({ agent: 'claude-code', detector: 'sensitive-access', severity: 'critical', kind: 'read', path: '/home/u/.aws/credentials', reason: 'grep ~/.aws/credentials: AWS credentials, outside this project' }),
    line({ agent: 'cursor', detector: 'sensitive-access', kind: 'read', path: '/home/u/.npmrc' }),
  ]

  it('names the agent next to what it touched when more than one agent did something', () => {
    const out = formatTouched(result(many), '30d', HOME, undefined, names)
    expect(out.split('\n')[0]).toBe('In the last 30d, from their own records: 2 conversations · 54,318 actions · 19 active days')
    expect(out).toMatch(/sensitive files touched\s+2\s+~\/\.aws\/credentials \(Claude Code\), ~\/\.npmrc \(Cursor\)/)
    expect(out).toMatch(/2026-09-21\s+Claude Code: grep ~\/\.aws\/credentials/)
  })

  it('leaves the names out when only one agent appears', () => {
    expect(formatTouched(result([many[1]]), '30d', HOME, undefined, names)).toMatch(/sensitive files touched\s+1\s+~\/\.npmrc$/m)
  })

  it('says there are no records instead of naming one agent\'s folder', () => {
    expect(formatTouched({ sessions: 0, toolCalls: 0, days: 0, summaries: [], findings: [], agents: {}, warnings: [] }, '30d', HOME, undefined, names)).toBe('No agent records in the last 30d.')
  })
})

describe('formatTouched when a reader failed', () => {
  it('names what could not be read instead of saying there are no records', () => {
    const out = formatTouched({ sessions: 0, toolCalls: 0, days: 0, summaries: [], findings: [], agents: {}, warnings: ['Hermes Agent: the sqlite3 program is not installed'] }, '30d', HOME, undefined, (id) => id)
    expect(out).toContain('Could not read: Hermes Agent: the sqlite3 program is not installed')
    expect(out).not.toBe('No agent records in the last 30d.')
  })
})
