import { describe, it, expect } from 'bun:test'
import { renderReport } from '../../src/report/html'
import { agentById } from '../../src/agents/registry'
import type { Overview } from '../../src/overview'
import type { ReplayResult } from '../../src/guard/replay'
import type { AuditLine } from '../../src/guard/types'

const NOW = Date.parse('2026-10-16T12:00:00Z')
const TOKEN = 'ghp_9fKq2LmNpR7sTvWx1yZaBc4dEfGh5JkL'
const finding = (over: Partial<AuditLine>): AuditLine => ({ ts: '2026-10-15T10:00:00.000Z', session_id: 's', event: 'finding', cwd: '/home/u/proj', severity: 'critical', alerted: true, ms: 0, ...over })

const overview: Overview = {
  processesChecked: true, warnings: [],
  agents: [
    { def: agentById('hermes')!, presence: { installed: ['~/.hermes'], running: true, toolServers: 0 }, setup: { toolServers: [], channels: ['Telegram'], schedules: 3, approvals: 'asks first', warnings: [] } },
    { def: agentById('chatgpt-atlas')!, presence: { installed: ['/Applications/ChatGPT Atlas.app'], lastUsed: NOW - 61 * 86_400_000, toolServers: 0 } },
  ],
}
const result: ReplayResult = {
  sessions: 2, toolCalls: 40, days: 3, summaries: [], warnings: [],
  agents: { hermes: { sessions: 2, toolCalls: 40, unknownActions: 0 } },
  findings: [
    finding({ agent: 'hermes', detector: 'sensitive-access', kind: 'read', path: '/home/u/<script>alert(1)</script>/.env', reason: `Read ~/<script>x</script>/.env with ${TOKEN}` }),
    finding({ agent: 'hermes', detector: 'secret-in-prompt', severity: 'high', kind: 'GitHub token' }),
  ],
}
const html = renderReport({ overview, result, now: NOW, home: '/home/u', span: '30 days' })

describe('renderReport', () => {
  it('is one self-contained page: a strict content policy, no script, nothing loaded from the network', () => {
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`)
    expect(html).not.toMatch(/<script/i)
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?https?:|url\(\s*["']?https?:|@import/i)
  })

  it('escapes every value from an agent\'s records and never shows a secret', () => {
    expect(html).toContain('&lt;script&gt;')
    expect(html).not.toContain(TOKEN)
  })

  it('tells a person, in plain words, which agents are here and what they did', () => {
    expect(html).toContain('Hermes Agent')
    expect(html).toContain('starts itself on 3 schedules')
    expect(html).toContain('reachable from Telegram')
    expect(html).toContain('its history is encrypted, havik cannot see it')
    expect(html).toContain('2 conversations')
    expect(html).toMatch(/secrets you pasted/i)
    expect(html).toMatch(/change|rotate/i)
    expect(html).not.toMatch(/\bMCP\b|tool call/)
  })
})

describe('renderReport when a reader failed', () => {
  it('says what could not be read instead of a clean result', () => {
    const failed = renderReport({ overview: { ...overview, warnings: ['Hermes Agent: the sqlite3 program is not installed, so havik cannot read this database'] }, result: { ...result, findings: [], toolCalls: 0, sessions: 0, days: 0, agents: {}, warnings: ['Hermes Agent: the sqlite3 program is not installed, so havik cannot read this database'] }, now: NOW, home: '/home/u', span: '30 days' })
    expect(failed).toContain('Could not read')
    expect(failed.split('sqlite3 program is not installed').length - 1).toBe(1)
    expect(failed).not.toContain('Nothing sensitive')
  })
})
