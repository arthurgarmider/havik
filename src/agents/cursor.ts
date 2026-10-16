import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { pathExists } from '../core/fs'
import { asArray, asRecord } from '../core/json'
import { sqliteQuery } from '../core/sqlite'
import type { Replayed } from '../guard/types'
import { parseArgs, pick, type Translation } from './normalize'
import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef, AgentSession, HistoryItem, HistoryOptions } from './types'

const DB = 'Library/Application Support/Cursor/User/globalStorage/state.vscdb'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MAX_RESULT = 65_536
const BASH = new Set(['run_terminal_command_v2', 'run_terminal_cmd', 'Shell'])
const READ = new Set(['read_file_v2', 'read_file', 'Read'])
const EDIT = new Set(['edit_file_v2', 'edit_file', 'search_replace', 'StrReplace', 'EditNotebook'])
const WRITE = new Set(['write', 'delete_file', 'Write', 'Delete'])
const GREP = new Set(['ripgrep_raw_search', 'grep', 'Grep'])
const GLOB = new Set(['glob_file_search', 'Glob'])
const FETCH = new Set(['web_fetch', 'WebFetch'])
const NO_ACCESS = new Set(['todo_write', 'task_v2', 'ask_question', 'read_lints', 'await', 'update_current_step', 'list_dir_v2', 'list_dir', 'web_search',
  'semantic_search_full', 'codebase_search', 'create_plan', 'switch_mode', 'LS', 'ReadLints', 'TodoWrite', 'SemanticSearch'])

const FILE_KEYS = ['relativeWorkspacePath', 'targetFile', 'path', 'file_path', 'target_file']

// Cursor's tools in havik's vocabulary. Tool servers come as mcp-<server>-<tool> with the call in params.tools[0].
export const cursorTool = (name: string, rawParams: unknown): Translation => {
  const args = parseArgs(rawParams)
  const file = pick(args, FILE_KEYS) ?? ''
  if (BASH.has(name)) {
    const cwd = pick(args, ['cwd'])
    return { tool_name: 'Bash', tool_input: { command: pick(args, ['command']) ?? '' }, ...(cwd ? { cwd } : {}) }
  }
  if (READ.has(name)) return { tool_name: 'Read', tool_input: { file_path: file } }
  if (EDIT.has(name)) return { tool_name: 'Edit', tool_input: { file_path: file } }
  if (WRITE.has(name)) return { tool_name: 'Write', tool_input: { file_path: file } }
  if (GREP.has(name)) {
    const path = pick(args, ['path'])
    return { tool_name: 'Grep', tool_input: { pattern: pick(args, ['pattern']) ?? '', ...(path ? { path } : {}) } }
  }
  if (GLOB.has(name)) return { tool_name: 'Glob', tool_input: { pattern: pick(args, ['globPattern', 'glob_pattern', 'pattern']) ?? '', path: pick(args, ['targetDirectory', 'target_directory', 'path']) } }
  if (FETCH.has(name)) return { tool_name: 'WebFetch', tool_input: { url: pick(args, ['url']) ?? '' } }
  if (name.startsWith('mcp-') || name === 'CallMcpTool') {
    const call = asRecord(asArray(args['tools'])[0] ?? args)
    const server = pick(call, ['serverName', 'server']) ?? 'unknown'
    const tool = pick(call, ['name', 'toolName']) ?? name
    return { tool_name: `mcp__${server}__${tool}`, tool_input: parseArgs(call['parameters'] ?? call['arguments']) }
  }
  return NO_ACCESS.has(name) ? null : undefined
}

const cwdOf = (uri: unknown, previous: string): string => {
  if (typeof uri !== 'string' || !uri.startsWith('file://')) return previous
  try {
    return fileURLToPath(uri)
  } catch {
    return previous
  }
}

// One conversation's messages, in time order: what you typed, each action with its result, and Cursor's replies.
const cursorSession = (id: string, rows: readonly Record<string, unknown>[], home: string): AgentSession => {
  const events: Replayed[] = []
  const unknown: Record<string, number> = {}
  let cwd = home
  const sorted = [...rows].sort((a, b) => String(a['at'] ?? '').localeCompare(String(b['at'] ?? '')))
  for (const r of sorted) {
    const at = Date.parse(String(r['at'] ?? '')) || 0
    cwd = cwdOf(r['ws'], cwd)
    const base = { session_id: id, cwd }
    const name = typeof r['name'] === 'string' ? r['name'] : undefined
    const text = typeof r['text'] === 'string' && r['text'].trim() ? r['text'] : undefined
    if (name) {
      const t = cursorTool(name, r['params'])
      if (t === undefined) unknown[name] = (unknown[name] ?? 0) + 1
      if (!t) continue
      const event = { ...base, cwd: t.cwd ?? cwd, tool_name: t.tool_name, tool_input: t.tool_input, tool_use_id: String(r['call'] ?? '') }
      events.push({ at, event: { ...event, hook_event_name: 'PreToolUse' } })
      if (typeof r['result'] === 'string') events.push({ at, event: { ...event, hook_event_name: 'PostToolUse', tool_response: r['result'] } })
    } else if (text && r['type'] === 1) {
      events.push({ at, event: { ...base, hook_event_name: 'UserPromptSubmit', prompt: text } })
    } else if (text) {
      events.push({ at, event: { ...base, hook_event_name: 'Stop', last_assistant_message: text } })
    }
  }
  return { id, startedBy: 'you', events, unknown }
}

// Cursor keeps every conversation in one SQLite database: read only the conversations of the window, each by key range.
async function* history(o: HistoryOptions): AsyncIterable<HistoryItem> {
  const db = join(o.home, DB)
  if (!(await pathExists(db))) return
  const cutoff = Math.floor(o.since === undefined ? 0 : o.now - o.since)
  const composers = await sqliteQuery(db, `select substr(key, 14) as id from cursorDiskKV where key >= 'composerData:' and key < 'composerData;' and json_valid(value) and coalesce(json_extract(value, '$.lastUpdatedAt'), json_extract(value, '$.createdAt'), ${Number.MAX_SAFE_INTEGER}) >= ${cutoff}`, { timeoutMs: 30_000 })
  if (!composers.ok) {
    yield { warning: composers.error }
    return
  }
  for (const c of composers.value) {
    const id = String(c['id'] ?? '')
    if (!UUID.test(id)) continue
    const rows = await sqliteQuery(db, `select json_extract(value, '$.type') as type, json_extract(value, '$.createdAt') as at, json_extract(value, '$.text') as text,
      json_extract(value, '$.toolFormerData.name') as name, json_extract(value, '$.toolFormerData.params') as params,
      substr(json_extract(value, '$.toolFormerData.result'), 1, ${MAX_RESULT}) as result, json_extract(value, '$.toolFormerData.toolCallId') as call,
      json_extract(value, '$.workspaceUris[0]') as ws
      from cursorDiskKV where key >= 'bubbleId:${id}:' and key < 'bubbleId:${id};' and json_valid(value)`, { timeoutMs: 30_000 })
    if (!rows.ok) {
      yield { warning: rows.error }
      continue
    }
    yield cursorSession(id, rows.value, o.home)
  }
}

const SUPPORT = '~/Library/Application Support/Cursor'

export const cursor: AgentDef = {
  id: 'cursor', name: 'Cursor', kind: 'coding assistant',
  footprint: { apps: ['Cursor'], bins: ['cursor'], dirs: ['~/.cursor'], activity: ['~/.cursor/projects', `${SUPPORT}/User/globalStorage/state.vscdb`], processes: ['Cursor'] },
  paths: {
    data: ['~/.cursor', SUPPORT],
    // Each project folder also holds Cursor's own working files (terminal output, tool descriptions): only transcripts are conversations.
    conversations: ['~/.cursor/projects/*/agent-transcripts', `${SUPPORT}/User/globalStorage/state.vscdb`, `${SUPPORT}/User/workspaceStorage`],
    // mcp.json holds the tool servers' tokens in env and headers: havik reads it only to name the servers.
    configs: ['~/.cursor/mcp.json'],
  },
  history,
  setup: async (home) => {
    const file = at(home, '.cursor/mcp.json')
    const config = await readConfig(file, 'json')
    return setupOf({ toolServers: serversIn(file, config.text, config.data?.['mcpServers']) }, [config])
  },
}
