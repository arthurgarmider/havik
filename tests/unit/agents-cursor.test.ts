import { describe, it, expect } from 'bun:test'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { cursorTool } from '../../src/agents/cursor'
import { agentById } from '../../src/agents/registry'
import type { AgentSession, HistoryItem } from '../../src/agents/types'
import { makeDb } from '../helpers/sqlite'
import { withTree } from '../helpers/tmp-tree'

const NOW = Date.parse('2026-10-16T12:00:00Z')
const DAY = 86_400_000
const A = '11111111-2222-3333-4444-555555555555'
const OLD = '99999999-8888-7777-6666-555555555555'
const UNDATED = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
const sql = (s: string) => s.replace(/'/g, "''")
const row = (key: string, value: object) => `insert into cursorDiskKV values ('${sql(key)}', '${sql(JSON.stringify(value))}');`
const bubble = (composer: string, id: string, at: string, value: object) => row(`bubbleId:${composer}:${id}`, { createdAt: at, ...value })
const tool = (name: string, params: object, result?: string) => ({ type: 2, toolFormerData: { name, params: JSON.stringify(params), result, toolCallId: `t-${name}` } })

const collect = async (items: AsyncIterable<HistoryItem>) => { const out: HistoryItem[] = []; for await (const i of items) out.push(i); return out }

describe('cursorTool: Cursor tool names in havik\'s vocabulary', () => {
  it('maps every known tool, and leaves unknown ones unknown', () => {
    const cases: Array<[string, object, unknown]> = [
      ['run_terminal_command_v2', { command: 'ls', cwd: '/w' }, { tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: '/w' }],
      ['run_terminal_cmd', { command: 'ls' }, { tool_name: 'Bash', tool_input: { command: 'ls' } }],
      ['read_file_v2', { targetFile: 'src/a.ts' }, { tool_name: 'Read', tool_input: { file_path: 'src/a.ts' } }],
      ['edit_file_v2', { relativeWorkspacePath: 'src/a.ts' }, { tool_name: 'Edit', tool_input: { file_path: 'src/a.ts' } }],
      ['search_replace', { relativeWorkspacePath: 'b.ts' }, { tool_name: 'Edit', tool_input: { file_path: 'b.ts' } }],
      ['write', { relativeWorkspacePath: 'c.ts', code: 'x' }, { tool_name: 'Write', tool_input: { file_path: 'c.ts' } }],
      ['delete_file', { relativeWorkspacePath: 'd.ts' }, { tool_name: 'Write', tool_input: { file_path: 'd.ts' } }],
      ['ripgrep_raw_search', { pattern: 'x', path: '/etc' }, { tool_name: 'Grep', tool_input: { pattern: 'x', path: '/etc' } }],
      ['glob_file_search', { targetDirectory: '/w', globPattern: '*.ts' }, { tool_name: 'Glob', tool_input: { pattern: '*.ts', path: '/w' } }],
      ['web_fetch', { url: 'https://docs.example.com' }, { tool_name: 'WebFetch', tool_input: { url: 'https://docs.example.com' } }],
      ['mcp-github-search', { tools: [{ name: 'search', serverName: 'github', parameters: '{"q":"x"}' }] }, { tool_name: 'mcp__github__search', tool_input: { q: 'x' } }],
      ['Shell', { command: 'pwd' }, { tool_name: 'Bash', tool_input: { command: 'pwd' } }],
      ['todo_write', {}, null],
      ['list_dir_v2', { targetDirectory: '/w' }, null],
      ['web_search', { searchTerm: 'x' }, null],
      ['mystery', {}, undefined],
    ]
    for (const [name, params, expected] of cases) expect([name, cursorTool(name, JSON.stringify(params))]).toEqual([name, expected])
  })
})

describe('Cursor history from its database', () => {
  const build = async (home: string) => {
    const dir = join(home, 'Library/Application Support/Cursor/User/globalStorage')
    await mkdir(dir, { recursive: true })
    const ws = pathToFileURL(join(home, 'proj')).href
    makeDb(join(dir, 'state.vscdb'), [
      'create table cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);',
      row(`composerData:${A}`, { composerId: A, createdAt: NOW - 2 * DAY, lastUpdatedAt: NOW - DAY }),
      row(`composerData:${OLD}`, { composerId: OLD, createdAt: NOW - 90 * DAY, lastUpdatedAt: NOW - 80 * DAY }),
      row(`composerData:${UNDATED}`, { composerId: UNDATED }),
      bubble(UNDATED, 'u1', '2026-10-14T08:00:00.000Z', tool('run_terminal_command_v2', { command: 'pwd' })),
      row("composerData:x'; drop table cursorDiskKV; --", { lastUpdatedAt: NOW }),
      bubble(A, 'b1', '2026-10-15T10:00:00.000Z', { type: 1, text: 'look at the npm config', workspaceUris: [ws] }),
      bubble(A, 'b2', '2026-10-15T10:00:05.000Z', { ...tool('run_terminal_command_v2', { command: 'cat ~/.npmrc' }, 'registry=https://registry.npmjs.org/'), workspaceUris: [ws] }),
      bubble(A, 'b3', '2026-10-15T10:00:09.000Z', tool('edit_file_v2', { relativeWorkspacePath: 'src/a.ts' })),
      bubble(A, 'b4', '2026-10-15T10:00:12.000Z', tool('mystery', {})),
      bubble(A, 'b5', '2026-10-15T10:00:15.000Z', { type: 2, text: 'Done.' }),
      bubble(OLD, 'o1', '2026-07-20T10:00:00.000Z', tool('run_terminal_command_v2', { command: 'ls' })),
    ].join('\n'))
  }

  it('reads the conversations of the window, by key range, with the workspace as the working folder', async () => {
    await withTree({}, async (home) => {
      await build(home)
      const items = await collect(agentById('cursor')!.history!({ home, since: 30 * DAY, now: NOW }))
      // A conversation without a last-updated date is read too; its messages' own times decide.
      expect(items.map((i) => ('warning' in i ? i.warning : i.id)).sort()).toEqual([A, UNDATED].sort())
      const s = items.find((i) => 'id' in i && i.id === A) as AgentSession
      expect(s.events.map((e) => `${e.event.hook_event_name}:${e.event.tool_name ?? ''}`)).toEqual(['UserPromptSubmit:', 'PreToolUse:Bash', 'PostToolUse:Bash', 'PreToolUse:Edit', 'Stop:'])
      expect(s.events[1].event.cwd).toBe(join(home, 'proj'))
      expect(s.events[3].event.tool_input).toEqual({ file_path: 'src/a.ts' })
      expect(s.unknown).toEqual({ mystery: 1 })
    })
  })

  it('says it could not read the database when sqlite3 is missing, never an empty history', async () => {
    await withTree({}, async (home) => {
      await build(home)
      const saved = process.env.PATH
      process.env.PATH = join(home, 'no-programs-here')
      try {
        const items = await collect(agentById('cursor')!.history!({ home, since: 30 * DAY, now: NOW }))
        expect(items.some((i) => 'warning' in i && i.warning.includes('sqlite3'))).toBe(true)
      } finally {
        process.env.PATH = saved
      }
    })
  })

  it('has nothing to say when Cursor keeps no database here', async () => {
    await withTree({}, async (home) => expect(await collect(agentById('cursor')!.history!({ home, since: 30 * DAY, now: NOW }))).toEqual([]))
  })
})
