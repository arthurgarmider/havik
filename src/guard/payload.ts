import { fileURLToPath } from 'node:url'
import { geminiTool } from '../agents/gemini-cli'
import { parseArgs } from '../agents/normalize'
import { asArray, asRecord } from '../core/json'
import type { HookEvent } from './types'

// Which agent sent a hook event, and what it says in havik's vocabulary. Claude Code's shape is the reference;
// Codex sends the same shape; Gemini CLI has its own event and tool names. Anything else is not read.
const GEMINI_EVENTS: Readonly<Record<string, string>> = { BeforeTool: 'PreToolUse', AfterTool: 'PostToolUse', BeforeAgent: 'UserPromptSubmit', AfterAgent: 'Stop', SessionStart: 'SessionStart' }

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

const claudeShaped = (e: Record<string, any>, agent?: string): HookEvent | undefined => {
  const [session_id, cwd, hook_event_name] = [str(e['session_id']), str(e['cwd']), str(e['hook_event_name'])]
  if (!session_id || !cwd || !hook_event_name) return undefined
  return {
    session_id, cwd, hook_event_name, agent,
    permission_mode: str(e['permission_mode']), tool_name: str(e['tool_name']), tool_input: e['tool_input'], tool_response: e['tool_response'],
    tool_use_id: str(e['tool_use_id']), prompt: str(e['prompt']), last_assistant_message: str(e['last_assistant_message']),
    agent_id: str(e['agent_id']), agent_type: str(e['agent_type']), source: str(e['source']), model: str(e['model']),
  }
}

// Codex reports a patch as apply_patch with the patch text in tool_input.command.
const fromCodex = (e: Record<string, any>): HookEvent | undefined => {
  const event = claudeShaped(e, 'codex')
  if (!event || event.tool_name !== 'apply_patch') return event
  return { ...event, tool_name: 'Patch', tool_input: { patch: str(asRecord(event.tool_input)['command']) ?? '' } }
}

const fromGemini = (e: Record<string, any>): HookEvent | undefined => {
  const base = claudeShaped({ ...e, hook_event_name: GEMINI_EVENTS[String(e['hook_event_name'])] }, 'gemini-cli')
  if (!base) return undefined
  const response = asRecord(e['tool_response'])['llmContent'] ?? e['tool_response']
  const extra = base.hook_event_name === 'Stop' ? { last_assistant_message: str(e['prompt_response']) } : {}
  if (!base.tool_name) return { ...base, ...extra }
  const t = geminiTool(base.tool_name, base.tool_input)
  if (!t) return { ...base, tool_response: response }
  return { ...base, tool_name: t.tool_name, tool_input: t.tool_input, tool_response: response, cwd: t.cwd ?? base.cwd }
}

export const parsePayload = (raw: string, declared?: string): HookEvent | undefined => {
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return undefined
  }
  const e = asRecord(data)
  if (declared === 'gemini-cli' || (declared === undefined && String(e['hook_event_name']) in GEMINI_EVENTS && e['hook_event_name'] !== 'SessionStart')) return fromGemini(e)
  if (declared === 'codex') return fromCodex(e)
  return claudeShaped(e)
}

// Cursor's after-hooks (havik installs no before-hook there: those decide permission). One payload can be two events:
// a finished shell command is the command and its output.
const workspaceOf = (e: Record<string, any>): string => {
  const root = String(asArray(e['workspace_roots'])[0] ?? '')
  if (!root.startsWith('file://')) return root
  try {
    return fileURLToPath(root)
  } catch {
    return root
  }
}

const fromCursor = (e: Record<string, any>): HookEvent[] => {
  const session_id = str(e['conversation_id'])
  if (!session_id) return []
  const base = { session_id, cwd: workspaceOf(e), agent: 'cursor', model: str(e['model']) }
  const name = String(e['hook_event_name'] ?? '')
  if (name === 'afterShellExecution') {
    const call = { ...base, tool_name: 'Bash', tool_input: { command: str(e['command']) ?? '' } }
    return [{ ...call, hook_event_name: 'PreToolUse' }, { ...call, hook_event_name: 'PostToolUse', tool_response: str(e['output']) ?? '' }]
  }
  if (name === 'afterFileEdit') return [{ ...base, hook_event_name: 'PreToolUse', tool_name: 'Edit', tool_input: { file_path: str(e['file_path']) ?? '' } }]
  if (name === 'afterMCPExecution') {
    const call = { ...base, tool_name: `mcp__${str(e['mcp_server_name']) ?? 'unknown'}__${str(e['tool_name']) ?? 'tool'}`, tool_input: parseArgs(e['tool_input']) }
    return [{ ...call, hook_event_name: 'PreToolUse' }, { ...call, hook_event_name: 'PostToolUse', tool_response: e['result_json'] }]
  }
  if (name === 'afterAgentResponse') return [{ ...base, hook_event_name: 'Stop', last_assistant_message: str(e['text']) ?? '' }]
  return []
}

// What the hook replays: Cursor's payloads can hold two events, every other agent's one.
export const eventsOfPayload = (raw: string, declared?: string): HookEvent[] => {
  if (declared !== 'cursor') {
    const event = parsePayload(raw, declared)
    return event ? [event] : []
  }
  try {
    return fromCursor(asRecord(JSON.parse(raw)))
  } catch {
    return []
  }
}
