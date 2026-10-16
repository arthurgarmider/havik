import { stat } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { findFiles, readTextOrNull } from '../core/fs'
import { asArray, asRecord } from '../core/json'
import type { Replayed } from '../guard/types'
import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef, HistoryItem, HistoryOptions } from './types'

// Claude Code's transcripts in ~/.claude/projects, one JSON object per line. Best-effort: the format is internal to Claude Code.

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

export const eventsOf = (text: string): Replayed[] => {
  const out: Replayed[] = []
  const calls = new Map<string, { name: string; input: unknown }>()
  let mode: string | undefined
  for (const raw of text.split('\n')) {
    let line: Record<string, any>
    try {
      line = asRecord(JSON.parse(raw))
    } catch {
      continue
    }
    const session_id = str(line['sessionId'])
    const cwd = str(line['cwd'])
    mode = str(line['permissionMode']) ?? mode
    if (!session_id || !cwd) continue
    const at = Date.parse(str(line['timestamp']) ?? '') || 0
    const base = { session_id, cwd, permission_mode: mode }
    // What the user typed or pasted; meta lines and compaction summaries are written by Claude Code, not the user.
    const content = asRecord(line['message'])['content']
    if (line['type'] === 'user' && !line['isMeta'] && !line['isCompactSummary'] && line['toolUseResult'] === undefined) {
      const prompt = typeof content === 'string' ? content : asArray(content).flatMap(b => (asRecord(b)['type'] === 'text' ? [String(asRecord(b)['text'] ?? '')] : [])).join('\n')
      if (prompt) out.push({ at, event: { ...base, hook_event_name: 'UserPromptSubmit', prompt } })
    }
    for (const block of asArray(asRecord(line['message'])['content'])) {
      const b = asRecord(block)
      // What the agent said; the live guard reads the same text from the Stop hook.
      if (line['type'] === 'assistant' && b['type'] === 'text' && typeof b['text'] === 'string' && b['text']) {
        out.push({ at, event: { ...base, hook_event_name: 'Stop', last_assistant_message: b['text'] } })
      }
      if (line['type'] === 'assistant' && b['type'] === 'tool_use' && typeof b['id'] === 'string' && typeof b['name'] === 'string') {
        calls.set(b['id'], { name: b['name'], input: b['input'] })
        out.push({ at, event: { ...base, hook_event_name: 'PreToolUse', tool_name: b['name'], tool_input: b['input'], tool_use_id: b['id'] } })
      }
      if (line['type'] === 'user' && b['type'] === 'tool_result' && typeof b['tool_use_id'] === 'string') {
        const call = calls.get(b['tool_use_id'])
        if (!call || b['is_error'] === true) continue
        const response = line['toolUseResult'] ?? b['content']
        out.push({ at, event: { ...base, hook_event_name: 'PostToolUse', tool_name: call.name, tool_input: call.input, tool_use_id: b['tool_use_id'], tool_response: response } })
      }
    }
  }
  return out
}


// Claude Code's own tools: the ones havik reads accesses from, and the ones that touch no file or host.
// Artifact publishes a page to claude.ai: it carries data out, and havik does not model it yet, so it stays unknown.
const UNDERSTOOD = new Set(['Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'Glob', 'Grep', 'Bash', 'WebFetch',
  'WebSearch', 'ToolSearch', 'StructuredOutput', 'Agent', 'Task', 'SubagentHandback', 'AskUserQuestion', 'Monitor', 'SendMessage', 'SendUserFile',
  'Skill', 'Workflow', 'ExitPlanMode', 'EnterPlanMode', 'ReadNotifications', 'TaskStop', 'TaskOutput', 'ListAgents', 'TodoWrite', 'KillShell', 'BashOutput', 'LSP',
  'TaskCreate', 'TaskUpdate', 'TaskList', 'TaskGet', 'ReportFindings', 'EnterWorktree', 'ExitWorktree'])

const isUnderstood = (e: Replayed): boolean => {
  const name = e.event.tool_name
  return name === undefined || UNDERSTOOD.has(name) || name.startsWith('mcp__')
}

const unknownOf = (events: readonly Replayed[]): Record<string, number> => {
  const unknown: Record<string, number> = {}
  for (const { event } of events) {
    const name = event.tool_name ?? ''
    if (event.hook_event_name !== 'PreToolUse' || UNDERSTOOD.has(name) || name.startsWith('mcp__')) continue
    unknown[name] = (unknown[name] ?? 0) + 1
  }
  return unknown
}

// A subagent's transcript lives under <session>/subagents/, and belongs to that session.
const sessionOf = (file: string): string =>
  basename(dirname(file)) === 'subagents' ? basename(dirname(dirname(file))) : basename(file, '.jsonl')

// One session at a time, so memory holds a single session's events.
async function* history(o: HistoryOptions): AsyncIterable<HistoryItem> {
  const dir = o.dir ?? join(o.home, '.claude', 'projects')
  const groups = new Map<string, string[]>()
  for (const file of await findFiles('**/*.jsonl', dir, { absolute: true, dot: true, deep: 5 })) {
    const info = await stat(file).catch(() => null)
    if (!info || (o.since !== undefined && o.now - info.mtimeMs > o.since)) continue
    groups.set(sessionOf(file), [...(groups.get(sessionOf(file)) ?? []), file])
  }
  for (const [id, files] of groups) {
    const events: Replayed[] = []
    for (const file of files) events.push(...eventsOf((await readTextOrNull(file)) ?? ''))
    yield { id, startedBy: 'you', events: events.filter(isUnderstood).sort((a, b) => a.at - b.at), unknown: unknownOf(events) }
  }
}

// Claude Code: the CLI, its IDE plugins and the desktop app's Code tab all keep their records in ~/.claude/projects.
export const claudeCode: AgentDef = {
  id: 'claude-code', name: 'Claude Code', kind: 'coding assistant',
  footprint: { bins: ['claude'], dirs: ['~/.claude'], activity: ['~/.claude/projects'], processes: ['claude'], packages: ['@anthropic-ai/claude-code'] },
  paths: {
    data: ['~/.claude', '~/.claude.json'],
    conversations: ['~/.claude/projects', '~/.claude/history.jsonl'],
    configs: ['~/.claude.json'],
    secrets: ['~/.claude/.credentials.json'],
  },
  history,
  setup: async (home) => {
    const file = at(home, '.claude.json')
    const global = await readConfig(file, 'json')
    const settings = await readConfig(at(home, '.claude/settings.json'), 'json')
    const projects = Object.values(asRecord(global.data?.['projects']))
    const mode = asRecord(settings.data?.['permissions'])['defaultMode']
    return setupOf({
      toolServers: [global.data?.['mcpServers'], ...projects.map(p => asRecord(p)['mcpServers'])].flatMap(e => serversIn(file, global.text, e)),
      ...(settings.data ? { approvals: mode === 'bypassPermissions' ? 'runs without asking' : 'asks first' } : {}),
    }, [global, settings])
  },
}
