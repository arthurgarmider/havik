import type { AgentDef } from './types'

// Agents havik can find and name, but whose history it does not read (yet, or ever): the note says why.
const AS = '~/Library/Application Support'

export const KNOWN: readonly AgentDef[] = [
  {
    id: 'chatgpt-atlas', name: 'ChatGPT Atlas', kind: 'browser agent', historyNote: 'its history is encrypted, havik cannot see it',
    // Its own background files change daily; only workspace-data tells when it was last used.
    footprint: { apps: ['ChatGPT Atlas'], dirs: [`${AS}/com.openai.atlas`], activity: [`${AS}/com.openai.atlas/workspace-data`], processes: ['ChatGPT Atlas'] },
    paths: { data: [`${AS}/com.openai.atlas`], conversations: [`${AS}/com.openai.atlas`] },
  },
  {
    id: 'chatgpt', name: 'ChatGPT (desktop app)', kind: 'desktop assistant', historyNote: 'its history is in your OpenAI account, not here',
    footprint: { apps: ['ChatGPT'], dirs: [`${AS}/com.openai.chat`], processes: ['ChatGPT'] },
    paths: { data: [`${AS}/com.openai.chat`] },
  },
  {
    id: 'comet', name: 'Perplexity Comet', kind: 'browser agent', historyNote: 'keeps its history where havik cannot read it',
    footprint: { apps: ['Comet'], dirs: [`${AS}/Comet`], processes: ['Comet'] },
    paths: { data: [`${AS}/Comet`] },
  },
  {
    id: 'jetbrains', name: 'JetBrains AI agents', kind: 'coding assistant', historyNote: 'its work shows under Claude Code or Codex',
    footprint: { dirs: ['~/.junie'], processes: ['claude-agent-acp', 'codex-acp', 'junie'] },
    paths: { data: ['~/.junie'], secrets: ['~/.junie/instances'] },
  },
  {
    id: 'copilot-cli', name: 'GitHub Copilot CLI', kind: 'coding assistant', historyNote: 'havik does not read its records yet',
    footprint: { bins: ['copilot'], dirs: ['~/.copilot'], activity: ['~/.copilot/session-state'], processes: ['copilot'] },
    paths: { data: ['~/.copilot'], conversations: ['~/.copilot/session-state'], configs: ['~/.copilot/mcp-config.json'] },
  },
  {
    id: 'windsurf', name: 'Windsurf', kind: 'coding assistant', historyNote: 'havik does not read its records yet',
    footprint: { apps: ['Windsurf', 'Devin'], dirs: ['~/.codeium/windsurf', '~/.config/devin'], processes: ['Windsurf', 'Devin'] },
    paths: { data: ['~/.codeium', '~/.config/devin'], configs: ['~/.codeium/windsurf/mcp_config.json', '~/.config/devin/mcp_config.json'] },
  },
  {
    id: 'cline', name: 'Cline', kind: 'coding assistant', historyNote: 'havik does not read its records yet',
    footprint: { dirs: [`${AS}/Code/User/globalStorage/saoudrizwan.claude-dev`] },
    paths: { data: [`${AS}/Code/User/globalStorage/saoudrizwan.claude-dev`], conversations: [`${AS}/Code/User/globalStorage/saoudrizwan.claude-dev/tasks`] },
  },
  {
    id: 'goose', name: 'Goose', kind: 'coding assistant', historyNote: 'havik does not read its records yet',
    footprint: { bins: ['goose'], dirs: ['~/.config/goose', '~/.local/share/goose'], processes: ['goose'] },
    paths: { data: ['~/.config/goose', '~/.local/share/goose'], conversations: ['~/.local/share/goose/sessions'], configs: ['~/.config/goose/config.yaml'] },
  },
  {
    id: 'opencode', name: 'opencode', kind: 'coding assistant', historyNote: 'havik does not read its records yet',
    footprint: { bins: ['opencode'], dirs: ['~/.local/share/opencode', '~/.config/opencode'], activity: ['~/.local/share/opencode/storage'], processes: ['opencode'] },
    paths: { data: ['~/.local/share/opencode', '~/.config/opencode'], conversations: ['~/.local/share/opencode/storage'] },
  },
  {
    id: 'aider', name: 'Aider', kind: 'coding assistant', historyNote: 'keeps its history inside each project folder',
    footprint: { bins: ['aider'], processes: ['aider'] },
    paths: { data: [] },
  },
  {
    id: 'zed', name: 'Zed agent', kind: 'coding assistant', historyNote: 'havik does not read its records yet',
    footprint: { apps: ['Zed'], dirs: [`${AS}/Zed/threads`], processes: ['zed'] },
    paths: { data: [`${AS}/Zed`], conversations: [`${AS}/Zed/threads`] },
  },
  {
    id: 'amp', name: 'Amp', kind: 'coding assistant', historyNote: 'keeps its history in your Amp account',
    footprint: { bins: ['amp'], dirs: ['~/.config/amp'], processes: ['amp'] },
    paths: { data: ['~/.config/amp'], configs: ['~/.config/amp/settings.json'] },
  },
  {
    id: 'grok', name: 'Grok', kind: 'desktop assistant', historyNote: 'havik does not read its records yet',
    footprint: { apps: ['Grok Bot', 'Grok'], dirs: ['~/.grokbot'], processes: ['Grok Bot', 'Grok'] },
    paths: { data: ['~/.grokbot', `${AS}/Grok Bot`], configs: ['~/.grokbot/settings.json'] },
  },
  {
    id: 'ollama', name: 'Ollama', kind: 'local model', historyNote: 'a model on this computer; it keeps no record of actions',
    footprint: { apps: ['Ollama'], bins: ['ollama'], dirs: ['~/.ollama'], processes: ['ollama', 'Ollama'] },
    paths: { data: ['~/.ollama'] },
  },
  {
    id: 'lm-studio', name: 'LM Studio', kind: 'local model', historyNote: 'a model on this computer; it keeps no record of actions',
    footprint: { apps: ['LM Studio'], dirs: ['~/.lmstudio'], processes: ['LM Studio'] },
    paths: { data: ['~/.lmstudio'] },
  },
  {
    id: 'cagent', name: 'Docker cagent', kind: 'agent runner', historyNote: 'keeps no history havik can read',
    footprint: { bins: ['cagent'], dirs: ['~/.cagent'], processes: ['cagent'] },
    paths: { data: ['~/.cagent', '~/.config/cagent'] },
  },
]
