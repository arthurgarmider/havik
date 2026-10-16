import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef } from './types'

export const antigravity: AgentDef = {
  id: 'antigravity', name: 'Antigravity', kind: 'coding assistant',
  footprint: { apps: ['Antigravity'], bins: ['agy'], dirs: ['~/.gemini/antigravity'], activity: ['~/.gemini/antigravity/brain'], processes: ['Antigravity', 'agy'] },
  paths: {
    data: ['~/.gemini/antigravity', '~/.gemini/config'],
    conversations: ['~/.gemini/antigravity/brain', '~/.gemini/antigravity/conversations'],
    configs: ['~/.gemini/config/mcp_config.json'],
  },
  setup: async (home) => {
    const file = at(home, '.gemini/config/mcp_config.json')
    const config = await readConfig(file, 'json')
    return setupOf({ toolServers: serversIn(file, config.text, config.data?.['mcpServers']) }, [config])
  },
}
