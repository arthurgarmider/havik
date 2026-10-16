import { describe, it, expect } from 'bun:test'
import { eventsOfPayload, parsePayload } from '../../src/guard/payload'
import { geminiTool } from '../../src/agents/gemini-cli'

const json = (o: object) => JSON.stringify(o)
const base = { session_id: 's', cwd: '/w', transcript_path: '/t' }

describe('parsePayload', () => {
  it('reads Claude Code\'s payload as before when no agent is named', () => {
    expect(parsePayload(json({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '/w/a' } }))).toMatchObject({ hook_event_name: 'PreToolUse', tool_name: 'Read', agent: undefined })
  })

  it('reads Codex\'s Claude-shaped payload, and a patch as the files it writes', () => {
    expect(parsePayload(json({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls' }, turn_id: 't' }), 'codex')).toMatchObject({ agent: 'codex', tool_name: 'Bash', tool_input: { command: 'ls' } })
    expect(parsePayload(json({ ...base, hook_event_name: 'PreToolUse', tool_name: 'apply_patch', tool_input: { command: '*** Begin Patch' } }), 'codex')).toMatchObject({ agent: 'codex', tool_name: 'Patch', tool_input: { patch: '*** Begin Patch' } })
  })

  it('reads Gemini CLI\'s events and tools in havik\'s vocabulary', () => {
    expect(parsePayload(json({ ...base, hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command: 'cat ~/.npmrc', directory: '/w/sub' } }), 'gemini-cli'))
      .toMatchObject({ agent: 'gemini-cli', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'cat ~/.npmrc' }, cwd: '/w/sub' })
    expect(parsePayload(json({ ...base, hook_event_name: 'AfterTool', tool_name: 'read_file', tool_input: { file_path: '/w/a' }, tool_response: { llmContent: 'text', returnDisplay: 'x' } }), 'gemini-cli'))
      .toMatchObject({ hook_event_name: 'PostToolUse', tool_name: 'Read', tool_response: 'text' })
    expect(parsePayload(json({ ...base, hook_event_name: 'BeforeAgent', prompt: 'hi' }), 'gemini-cli')).toMatchObject({ hook_event_name: 'UserPromptSubmit', prompt: 'hi' })
    expect(parsePayload(json({ ...base, hook_event_name: 'AfterAgent', prompt: 'hi', prompt_response: 'Done.' }), 'gemini-cli')).toMatchObject({ hook_event_name: 'Stop', last_assistant_message: 'Done.' })
  })

  it('recognises Gemini CLI by its event names even when no agent is named', () => {
    expect(parsePayload(json({ ...base, hook_event_name: 'BeforeTool', tool_name: 'read_file', tool_input: { file_path: '/w/a' } }))?.agent).toBe('gemini-cli')
  })

  it('reads nothing from a payload in another shape (Copilot, VS Code, Devin reading Claude\'s settings)', () => {
    expect(parsePayload(json({ sessionId: 's', toolName: 'bash', toolArgs: '{}', cwd: '/w' }))).toBeUndefined()
    expect(parsePayload('not json')).toBeUndefined()
  })
})

describe('geminiTool', () => {
  it('maps Gemini CLI tools, and leaves unknown ones unknown', () => {
    const cases: Array<[string, object, unknown]> = [
      ['run_shell_command', { command: 'ls' }, { tool_name: 'Bash', tool_input: { command: 'ls' } }],
      ['read_file', { absolute_path: '/w/a' }, { tool_name: 'Read', tool_input: { file_path: '/w/a' } }],
      ['write_file', { file_path: '/w/b', content: 'x' }, { tool_name: 'Write', tool_input: { file_path: '/w/b' } }],
      ['replace', { file_path: '/w/c', old_string: 'a', new_string: 'b' }, { tool_name: 'Edit', tool_input: { file_path: '/w/c' } }],
      ['glob', { pattern: '*.ts', path: '/w' }, { tool_name: 'Glob', tool_input: { pattern: '*.ts', path: '/w' } }],
      ['search_file_content', { pattern: 'x', path: '/w' }, { tool_name: 'Grep', tool_input: { pattern: 'x', path: '/w' } }],
      ['web_fetch', { prompt: 'summarise https://docs.example.com/a please' }, { tool_name: 'WebFetch', tool_input: { url: 'https://docs.example.com/a' } }],
      ['mcp_github_search', { q: 'x' }, { tool_name: 'mcp__github__search', tool_input: { q: 'x' } }],
      ['list_directory', { path: '/w' }, null],
      ['google_web_search', { query: 'x' }, null],
      ['mystery', {}, undefined],
    ]
    for (const [name, input, expected] of cases) expect([name, geminiTool(name, input)]).toEqual([name, expected])
  })
})

describe('eventsOfPayload: Cursor\'s after-hooks', () => {
  const cursor = { conversation_id: 'c-1', generation_id: 'g', hook_event_name: '', workspace_roots: ['/w'], cursor_version: '2.0' }
  const of = (o: object) => eventsOfPayload(json({ ...cursor, ...o }), 'cursor').map((e) => `${e.hook_event_name}:${e.tool_name ?? ''}:${e.agent}:${e.session_id}:${e.cwd}`)

  it('turns a finished shell command into the command and its output', () => {
    expect(of({ hook_event_name: 'afterShellExecution', command: 'cat ~/.npmrc', output: 'registry=x' })).toEqual(['PreToolUse:Bash:cursor:c-1:/w', 'PostToolUse:Bash:cursor:c-1:/w'])
    expect(eventsOfPayload(json({ ...cursor, hook_event_name: 'afterShellExecution', command: 'ls', output: 'a' }), 'cursor')[1].tool_response).toBe('a')
  })

  it('reads a file edit, a tool-server call with its result, and the reply', () => {
    expect(of({ hook_event_name: 'afterFileEdit', file_path: '/w/a.ts', edits: [] })).toEqual(['PreToolUse:Edit:cursor:c-1:/w'])
    expect(of({ hook_event_name: 'afterMCPExecution', tool_name: 'search', mcp_server_name: 'github', tool_input: '{"q":"x"}', result_json: '{}' })).toEqual(['PreToolUse:mcp__github__search:cursor:c-1:/w', 'PostToolUse:mcp__github__search:cursor:c-1:/w'])
    expect(of({ hook_event_name: 'afterAgentResponse', text: 'Done.' })).toEqual(['Stop::cursor:c-1:/w'])
  })

  it('reads nothing from a before-hook, which havik never installs in Cursor', () => {
    expect(of({ hook_event_name: 'beforeShellExecution', command: 'ls' })).toEqual([])
  })

  it('wraps the other agents\' single event', () => {
    expect(eventsOfPayload(json({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: {} })).length).toBe(1)
  })
})
