import { asArray } from '../core/json'
import { parseArgs, pick, type Translation } from './normalize'
import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef } from './types'

const URL_IN_TEXT = /https?:\/\/[^\s'"<>)]+/
const NO_ACCESS = new Set(['list_directory', 'ls', 'google_web_search', 'web_search', 'save_memory', 'write_todos', 'activate_skill'])

// Gemini CLI's tools in havik's vocabulary.
export const geminiTool = (name: string, raw: unknown): Translation => {
  const args = parseArgs(raw)
  const file = pick(args, ['file_path', 'absolute_path', 'path']) ?? ''
  switch (name) {
    case 'run_shell_command': {
      const cwd = pick(args, ['directory', 'dir_path'])
      return { tool_name: 'Bash', tool_input: { command: pick(args, ['command']) ?? '' }, ...(cwd ? { cwd } : {}) }
    }
    case 'read_file': return { tool_name: 'Read', tool_input: { file_path: file } }
    // read_many_files reads several; the first stands for them.
    case 'read_many_files': return { tool_name: 'Read', tool_input: { file_path: String(asArray(args['paths'])[0] ?? '') } }
    case 'write_file': return { tool_name: 'Write', tool_input: { file_path: file } }
    case 'replace': return { tool_name: 'Edit', tool_input: { file_path: file } }
    case 'glob': return { tool_name: 'Glob', tool_input: { pattern: pick(args, ['pattern']) ?? '', ...(pick(args, ['path', 'dir_path']) ? { path: pick(args, ['path', 'dir_path']) } : {}) } }
    case 'search_file_content': case 'grep_search': return { tool_name: 'Grep', tool_input: { pattern: pick(args, ['pattern']) ?? '', ...(pick(args, ['path', 'dir_path']) ? { path: pick(args, ['path', 'dir_path']) } : {}) } }
    case 'web_fetch': return { tool_name: 'WebFetch', tool_input: { url: URL_IN_TEXT.exec(pick(args, ['prompt', 'url']) ?? '')?.[0] ?? '' } }
  }
  if (name.startsWith('mcp_')) {
    const [server, ...tool] = name.slice(4).split('_')
    return { tool_name: `mcp__${server}__${tool.join('_')}`, tool_input: args }
  }
  return NO_ACCESS.has(name) ? null : undefined
}

export const geminiCli: AgentDef = {
  id: 'gemini-cli', name: 'Gemini CLI', kind: 'coding assistant',
  footprint: { bins: ['gemini'], dirs: ['~/.gemini/settings.json', '~/.gemini/tmp'], activity: ['~/.gemini/tmp'], processes: ['gemini'] },
  paths: {
    data: ['~/.gemini'],
    conversations: ['~/.gemini/tmp'],
    configs: ['~/.gemini/settings.json'],
    secrets: ['~/.gemini/oauth_creds.json', '~/.gemini/google_accounts.json'],
  },
  setup: async (home) => {
    const file = at(home, '.gemini/settings.json')
    const config = await readConfig(file, 'json')
    return setupOf({ toolServers: serversIn(file, config.text, config.data?.['mcpServers']) }, [config])
  },
}
