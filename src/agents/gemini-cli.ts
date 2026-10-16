import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef } from './types'

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
