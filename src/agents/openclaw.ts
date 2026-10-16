import { asRecord } from '../core/json'
import { at, channelName, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef } from './types'

export const openclaw: AgentDef = {
  id: 'openclaw', name: 'OpenClaw', kind: 'self-running agent',
  footprint: { bins: ['openclaw'], dirs: ['~/.openclaw'], activity: ['~/.openclaw/agents'], processes: ['openclaw'] },
  paths: {
    data: ['~/.openclaw'],
    conversations: ['~/.openclaw/agents'],
    configs: ['~/.openclaw/openclaw.json'],
    secrets: ['~/.openclaw/credentials'],
  },
  setup: async (home) => {
    const file = at(home, '.openclaw/openclaw.json')
    const config = await readConfig(file, 'json')
    const channels = Object.entries(asRecord(config.data?.['channels'])).filter(([, c]) => asRecord(c)['enabled'] !== false).flatMap(([id]) => channelName(id) ?? [])
    return setupOf({ toolServers: serversIn(file, config.text, asRecord(config.data?.['mcp'])['servers']), channels }, [config])
  },
}
