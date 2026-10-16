import { describe, it, expect } from 'bun:test'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { hermesTool } from '../../src/agents/hermes'
import { agentById } from '../../src/agents/registry'
import { accesses } from '../../src/guard/accesses'
import { replayAgents } from '../../src/guard/replay'
import { DEFAULTS } from '../../src/core/sensitivity'
import { DEFAULT_CONFIG, guardMap } from '../../src/guard/policy'
import { makeDb } from '../helpers/sqlite'
import { withTree } from '../helpers/tmp-tree'

const NOW = Date.parse('2026-10-16T12:00:00Z')
const DAY = 86_400_000
const sec = (ms: number) => ms / 1000
const q = (s: string) => s.replace(/'/g, "''")

const withTmp = async <T>(dir: string, run: () => Promise<T>): Promise<T> => {
  const saved = process.env.TMPDIR
  process.env.TMPDIR = join(dir, 'tmp')
  try { return await run() } finally { if (saved === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = saved }
}
const replay = (home: string, id: string) => replayAgents({ home, config: DEFAULT_CONFIG, map: guardMap(DEFAULTS, DEFAULT_CONFIG), now: NOW, since: 30 * DAY, agents: [agentById(id)!] })

describe('hermesTool', () => {
  it('maps Hermes tools, and leaves unknown ones unknown', () => {
    const cases: Array<[string, object, unknown]> = [
      ['terminal', { command: 'ls' }, { tool_name: 'Bash', tool_input: { command: 'ls' } }],
      ['read_file', { path: '/w/a' }, { tool_name: 'Read', tool_input: { file_path: '/w/a' } }],
      ['write_file', { path: '/w/b', content: 'x' }, { tool_name: 'Write', tool_input: { file_path: '/w/b' } }],
      ['patch', { path: '/w/c', old_string: 'a', new_string: 'b' }, { tool_name: 'Edit', tool_input: { file_path: '/w/c' } }],
      ['search_files', { pattern: 'x', path: '/w', target: 'content' }, { tool_name: 'Grep', tool_input: { pattern: 'x', path: '/w' } }],
      ['browser_navigate', { url: 'https://example.com' }, { tool_name: 'WebFetch', tool_input: { url: 'https://example.com' } }],
      ['web_extract', { urls: ['https://a.example.com', 'https://b.example.com'] }, { tool_name: 'WebFetch', tool_input: { url: 'https://a.example.com' } }],
      ['execute_code', { code: 'print(1)' }, { tool_name: 'InlineCode', tool_input: { code: 'print(1)' } }],
      ['send_message', { target: 'telegram:12345', message: 'hi' }, { tool_name: 'Send', tool_input: { channel: 'telegram' } }],
      ['mcp_docs_search', { q: 'x' }, { tool_name: 'mcp__docs__search', tool_input: { q: 'x' } }],
      ['web_search', { query: 'x' }, null],
      ['cronjob', { action: 'create' }, null],
      ['mystery', {}, undefined],
    ]
    for (const [name, args, expected] of cases) expect([name, hermesTool(name, JSON.stringify(args))]).toEqual([name, expected])
  })
})

describe('accesses: messages and inline code', () => {
  it('sends to the chat app a message goes to, and records inline code', () => {
    expect(accesses('Send', { channel: 'telegram' }, '/w', '/home/u')).toEqual([{ kind: 'send', host: 'api.telegram.org', via: 'Send' }])
    expect(accesses('Send', { channel: 'somewhere' }, '/w', '/home/u')).toEqual([{ kind: 'send', host: 'somewhere', via: 'Send' }])
    expect(accesses('InlineCode', { code: 'x' }, '/w', '/home/u')).toEqual([{ kind: 'inline-code', path: '/w', via: 'InlineCode' }])
  })
})

describe('Hermes history from its database', () => {
  it('a scheduled run that reads a key file and then sends a chat message', async () => {
    await withTree({}, async (dir) => {
      const home = join(dir, 'home')
      await mkdir(join(home, '.hermes'), { recursive: true })
      const call = (id: string, name: string, args: object) => q(JSON.stringify([{ id, type: 'function', function: { name, arguments: JSON.stringify(args) } }]))
      makeDb(join(home, '.hermes/state.db'), [
        'create table sessions (id TEXT, source TEXT, started_at REAL, ended_at REAL);',
        'create table messages (id INTEGER, session_id TEXT, role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL);',
        `insert into sessions values ('h1', 'cron', ${sec(NOW - DAY)}, ${sec(NOW - DAY + 60_000)}), ('h0', 'cli', ${sec(NOW - 90 * DAY)}, ${sec(NOW - 90 * DAY)});`,
        `insert into messages values (1, 'h1', 'user', 'daily check', null, null, null, ${sec(NOW - DAY)});`,
        `insert into messages values (2, 'h1', 'assistant', '', null, '${call('c1', 'read_file', { path: join(home, '.npmrc') })}', null, ${sec(NOW - DAY + 1_000)});`,
        `insert into messages values (3, 'h1', 'tool', 'registry=https://registry.npmjs.org/', 'c1', null, 'read_file', ${sec(NOW - DAY + 2_000)});`,
        `insert into messages values (4, 'h1', 'assistant', '', null, '${call('c2', 'send_message', { target: 'telegram:1', message: 'report' })}', null, ${sec(NOW - DAY + 3_000)});`,
        `insert into messages values (5, 'h1', 'assistant', 'Done.', null, null, null, ${sec(NOW - DAY + 4_000)});`,
        `insert into messages values (6, 'h0', 'user', 'old', null, null, null, ${sec(NOW - 90 * DAY)});`,
      ].join('\n'))
      const r = await withTmp(dir, () => replay(home, 'hermes'))
      expect(r.findings.map((f) => `${f.agent} ${f.detector} ${f.host ?? ''}`.trim())).toEqual(['hermes sensitive-access', 'hermes data-leaving api.telegram.org'])
      expect(r.agents.hermes).toMatchObject({ sessions: 1, toolCalls: 2 })
      expect(r.summaries[0].session).toBe('h1')
    })
  })
})

describe('Claude desktop app history: the Cowork audit', () => {
  it('reads Cowork sessions as Claude Code-shaped events, credited to the desktop app', async () => {
    await withTree({}, async (dir) => {
      const home = join(dir, 'home')
      const at = new Date(NOW - DAY).toISOString()
      const lines = [
        { type: 'system', subtype: 'init', session_id: 'w1', cwd: join(home, 'work'), timestamp: at },
        { type: 'user', session_id: 'w1', timestamp: at, message: { role: 'user', content: 'tidy the folder' } },
        { type: 'assistant', session_id: 'w1', timestamp: at, message: { content: [{ type: 'tool_use', id: 'u1', name: 'Read', input: { file_path: join(home, '.npmrc') } }] } },
      ].map((l) => JSON.stringify({ ...l, _audit_hmac: 'x' })).join('\n')
      await Bun.write(join(home, 'Library/Application Support/Claude/local-agent-mode-sessions/a/b/audit.jsonl'), lines)
      const r = await withTmp(dir, () => replay(home, 'claude-desktop'))
      expect(r.findings.map((f) => `${f.agent} ${f.detector}`)).toEqual(['claude-desktop sensitive-access'])
      expect(r.agents['claude-desktop']).toMatchObject({ sessions: 1, toolCalls: 1 })
    })
  })
})
