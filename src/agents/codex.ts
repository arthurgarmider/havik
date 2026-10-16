import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { findFiles, readTextOrNull } from '../core/fs'
import { asRecord } from '../core/json'
import type { Replayed } from '../guard/types'
import { parseArgs, pick, shellText, type Translation } from './normalize'
import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef, HistoryItem, HistoryOptions } from './types'

const NO_ACCESS = new Set(['update_plan', 'web_search', 'write_stdin', 'request_user_input'])

// Codex's tools in havik's vocabulary.
export const codexTool = (name: string, raw: unknown): Translation => {
  const args = parseArgs(raw)
  const cwd = pick(args, ['workdir', 'cwd'])
  if (['shell', 'shell_command', 'exec_command', 'local_shell'].includes(name)) {
    return { tool_name: 'Bash', tool_input: { command: shellText(args['command'] ?? args['cmd']) }, ...(cwd ? { cwd } : {}) }
  }
  if (name === 'apply_patch') return { tool_name: 'Patch', tool_input: { patch: typeof raw === 'string' && !raw.trimStart().startsWith('{') ? raw : pick(args, ['input', 'patch']) ?? '' } }
  if (name === 'view_image') return { tool_name: 'Read', tool_input: { file_path: pick(args, ['path']) ?? '' } }
  if (name.startsWith('mcp__')) return { tool_name: name, tool_input: args }
  if (name.includes('__')) return { tool_name: `mcp__${name}`, tool_input: args }
  return NO_ACCESS.has(name) ? null : undefined
}

// One rollout file is one conversation: session_meta, then response items and events, one JSON object per line.
export const codexEvents = (text: string): { id?: string; events: Replayed[]; unknown: Record<string, number> } => {
  const events: Replayed[] = []
  const unknown: Record<string, number> = {}
  const calls = new Map<string, { name: string; input: unknown; cwd: string }>()
  let id: string | undefined
  let cwd = ''
  for (const raw of text.split('\n')) {
    let line: Record<string, any>
    try {
      line = asRecord(JSON.parse(raw))
    } catch {
      continue
    }
    const p = asRecord(line['payload'])
    const atMs = Date.parse(String(line['timestamp'] ?? '')) || 0
    if (line['type'] === 'session_meta') {
      id = typeof p['id'] === 'string' ? p['id'] : id
      cwd = typeof p['cwd'] === 'string' ? p['cwd'] : cwd
      continue
    }
    if (line['type'] === 'turn_context' && typeof p['cwd'] === 'string') cwd = p['cwd']
    const base = { session_id: id ?? 'codex', cwd }
    if (line['type'] === 'event_msg' && p['type'] === 'user_message' && typeof p['message'] === 'string') {
      events.push({ at: atMs, event: { ...base, hook_event_name: 'UserPromptSubmit', prompt: p['message'] } })
    } else if (line['type'] === 'event_msg' && p['type'] === 'agent_message' && typeof p['message'] === 'string') {
      events.push({ at: atMs, event: { ...base, hook_event_name: 'Stop', last_assistant_message: p['message'] } })
    } else if (line['type'] === 'response_item' && (p['type'] === 'function_call' || p['type'] === 'custom_tool_call')) {
      const name = String(p['name'] ?? '')
      const t = codexTool(name, p['type'] === 'custom_tool_call' ? p['input'] : p['arguments'])
      if (t === undefined) unknown[name] = (unknown[name] ?? 0) + 1
      if (!t) continue
      const where = t.cwd ?? cwd
      const callId = String(p['call_id'] ?? '')
      calls.set(callId, { name: t.tool_name, input: t.tool_input, cwd: where })
      events.push({ at: atMs, event: { ...base, cwd: where, hook_event_name: 'PreToolUse', tool_name: t.tool_name, tool_input: t.tool_input, tool_use_id: callId } })
    } else if (line['type'] === 'response_item' && (p['type'] === 'function_call_output' || p['type'] === 'custom_tool_call_output')) {
      const c = calls.get(String(p['call_id'] ?? ''))
      if (c) events.push({ at: atMs, event: { ...base, cwd: c.cwd, hook_event_name: 'PostToolUse', tool_name: c.name, tool_input: c.input, tool_use_id: String(p['call_id']), tool_response: p['output'] } })
    }
  }
  return { id, events, unknown }
}

async function* history(o: HistoryOptions): AsyncIterable<HistoryItem> {
  const dir = join(o.home, '.codex', 'sessions')
  for (const file of await findFiles('**/rollout-*.jsonl', dir, { absolute: true, deep: 6 })) {
    const info = await stat(file).catch(() => null)
    if (!info || (o.since !== undefined && o.now - info.mtimeMs > o.since)) continue
    const { id, events, unknown } = codexEvents((await readTextOrNull(file)) ?? '')
    yield { id: id ?? file, startedBy: 'you', events, unknown }
  }
}

export const codex: AgentDef = {
  id: 'codex', name: 'Codex', kind: 'coding assistant',
  footprint: { apps: ['Codex'], bins: ['codex'], dirs: ['~/.codex'], activity: ['~/.codex/sessions'], processes: ['codex'] },
  paths: {
    data: ['~/.codex'],
    conversations: ['~/.codex/sessions', '~/.codex/history.jsonl'],
    configs: ['~/.codex/config.toml'],
    secrets: ['~/.codex/auth.json'],
  },
  history,
  setup: async (home) => {
    const file = at(home, '.codex/config.toml')
    const config = await readConfig(file, 'toml')
    // approval_policy "never" runs every command without asking; the other policies ask at some point.
    const policy = config.data?.['approval_policy']
    return setupOf({
      toolServers: serversIn(file, config.text, config.data?.['mcp_servers']),
      ...(config.data ? { approvals: policy === 'never' ? 'runs without asking' : 'asks first' } : {}),
    }, [config])
  },
}
