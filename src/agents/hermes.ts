import { join } from 'node:path'
import { pathExists } from '../core/fs'
import { sqliteQuery } from '../core/sqlite'
import { asArray, asRecord } from '../core/json'
import type { Replayed } from '../guard/types'
import { parseArgs, pick, type Translation } from './normalize'
import { at, channelName, readConfig, setupOf } from './setup'
import type { AgentDef, AgentSession, HistoryItem, HistoryOptions } from './types'

const SESSION_ID = /^[\w.:-]{1,128}$/
const MAX_TEXT = 65_536
const NO_ACCESS = new Set(['web_search', 'cronjob', 'skill_view', 'skills_list', 'process', 'clarify', 'browser_snapshot', 'browser_type', 'browser_press', 'browser_click', 'computer_use', 'memory', 'todo', 'delegate', 'vision_analyze'])

// Hermes's tools in havik's vocabulary.
export const hermesTool = (name: string, raw: unknown): Translation => {
  const args = parseArgs(raw)
  const path = pick(args, ['path', 'file_path']) ?? ''
  switch (name) {
    case 'terminal': return { tool_name: 'Bash', tool_input: { command: pick(args, ['command']) ?? '' } }
    case 'read_file': return { tool_name: 'Read', tool_input: { file_path: path } }
    case 'write_file': return { tool_name: 'Write', tool_input: { file_path: path } }
    case 'patch': return { tool_name: 'Edit', tool_input: { file_path: path } }
    case 'search_files': return args['target'] === 'files'
      ? { tool_name: 'Glob', tool_input: { pattern: pick(args, ['file_glob', 'pattern']) ?? '', path: pick(args, ['path']) } }
      : { tool_name: 'Grep', tool_input: { pattern: pick(args, ['pattern']) ?? '', ...(pick(args, ['path']) ? { path: pick(args, ['path']) } : {}) } }
    case 'browser_navigate': return { tool_name: 'WebFetch', tool_input: { url: pick(args, ['url']) ?? '' } }
    // web_extract fetches several pages; the first stands for them.
    case 'web_extract': return { tool_name: 'WebFetch', tool_input: { url: String(asArray(args['urls'])[0] ?? '') } }
    case 'execute_code': return { tool_name: 'InlineCode', tool_input: { code: pick(args, ['code']) ?? '' } }
    // The target names the chat app first (telegram:<chat>); the chat itself is never kept.
    case 'send_message': return { tool_name: 'Send', tool_input: { channel: (pick(args, ['target', 'platform']) ?? '').split(':')[0] } }
  }
  if (name.startsWith('mcp_')) {
    const [server, ...tool] = name.slice(4).split('_')
    return { tool_name: `mcp__${server}__${tool.join('_')}`, tool_input: args }
  }
  return NO_ACCESS.has(name) ? null : undefined
}

const msOf = (t: unknown): number => (typeof t === 'number' ? (t < 1e12 ? t * 1000 : t) : 0)

const startedByOf = (source: string): AgentSession['startedBy'] =>
  source === 'cron' ? 'schedule' : source === 'cli' ? 'you' : channelName(source) ? 'chat' : 'unknown'

// One session's messages: the prompt (yours, or its schedule's), each tool call with its result, and its replies.
const hermesSession = (id: string, source: string, rows: readonly Record<string, unknown>[], home: string): AgentSession => {
  const events: Replayed[] = []
  const unknown: Record<string, number> = {}
  const calls = new Map<string, { tool_name: string; tool_input: unknown }>()
  const base = { session_id: id, cwd: home }
  for (const r of rows) {
    const at = msOf(r['timestamp'])
    const content = typeof r['content'] === 'string' && r['content'].trim() ? r['content'] : undefined
    if (r['role'] === 'user' && content) events.push({ at, event: { ...base, hook_event_name: 'UserPromptSubmit', prompt: content } })
    if (r['role'] === 'assistant') {
      for (const c of asArray(parseJsonArray(r['tool_calls']))) {
        const fn = asRecord(asRecord(c)['function'])
        const name = String(fn['name'] ?? '')
        const t = hermesTool(name, fn['arguments'])
        if (t === undefined) unknown[name] = (unknown[name] ?? 0) + 1
        if (!t) continue
        const callId = String(asRecord(c)['id'] ?? asRecord(c)['call_id'] ?? '')
        calls.set(callId, t)
        events.push({ at, event: { ...base, hook_event_name: 'PreToolUse', tool_name: t.tool_name, tool_input: t.tool_input, tool_use_id: callId } })
      }
      if (content) events.push({ at, event: { ...base, hook_event_name: 'Stop', last_assistant_message: content } })
    }
    if (r['role'] === 'tool') {
      const t = calls.get(String(r['tool_call_id'] ?? ''))
      if (t && content) events.push({ at, event: { ...base, hook_event_name: 'PostToolUse', ...t, tool_use_id: String(r['tool_call_id']), tool_response: content } })
    }
  }
  return { id, startedBy: startedByOf(source), events, unknown }
}

const parseJsonArray = (raw: unknown): unknown => {
  if (typeof raw !== 'string') return []
  try {
    return JSON.parse(raw)
  } catch {
    return []
  }
}

// Hermes keeps its sessions in SQLite; read the sessions of the window, one at a time.
async function* history(o: HistoryOptions): AsyncIterable<HistoryItem> {
  const db = join(o.home, '.hermes', 'state.db')
  if (!(await pathExists(db))) return
  const cutoff = o.since === undefined ? 0 : (o.now - o.since) / 1000
  const sessions = await sqliteQuery(db, `select id, source from sessions where coalesce(ended_at, started_at, ${Number.MAX_SAFE_INTEGER}) >= ${cutoff}`)
  if (!sessions.ok) {
    yield { warning: sessions.error }
    return
  }
  for (const s of sessions.value) {
    const id = String(s['id'] ?? '')
    if (!SESSION_ID.test(id)) continue
    const rows = await sqliteQuery(db, `select role, substr(content, 1, ${MAX_TEXT}) as content, tool_calls, tool_call_id, timestamp from messages where session_id = '${id}' order by id`)
    if (!rows.ok) {
      yield { warning: rows.error }
      continue
    }
    yield hermesSession(id, String(s['source'] ?? ''), rows.value, o.home)
  }
}

// Hermes Agent runs by itself: a scheduler starts its sessions, and chat apps can reach it.
export const hermes: AgentDef = {
  id: 'hermes', name: 'Hermes Agent', kind: 'self-running agent',
  footprint: { bins: ['hermes'], dirs: ['~/.hermes'], activity: ['~/.hermes/state.db', '~/.hermes/sessions'], processes: ['hermes'] },
  paths: {
    data: ['~/.hermes'],
    conversations: ['~/.hermes/state.db', '~/.hermes/sessions'],
    configs: ['~/.hermes/config.yaml'],
    secrets: ['~/.hermes/.env', '~/.hermes/auth.json'],
  },
  history,
  setup: async (home) => {
    const config = await readConfig(at(home, '.hermes/config.yaml'), 'yaml')
    const jobs = await readConfig(at(home, '.hermes/cron/jobs.json'), 'json')
    // Reachable from a chat app when that app has started sessions: evidence, not the presence of a settings section.
    const db = at(home, '.hermes/state.db')
    const sources = (await pathExists(db)) ? await sqliteQuery(db, 'select distinct source from sessions') : { ok: true as const, value: [] }
    const channels = sources.ok ? sources.value.flatMap(r => channelName(String(r['source'] ?? '')) ?? []) : []
    const mode = asRecord(config.data?.['approvals'])['mode']
    return setupOf({
      channels,
      schedules: asArray(jobs.data?.['jobs']).length,
      ...(config.data ? { approvals: ['off', 'auto', 'yolo', 'never'].includes(String(mode)) ? 'runs without asking' : 'asks first' } : {}),
      warnings: sources.ok ? [] : [sources.error],
    }, [config, jobs])
  },
}
