import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import type { McpServerInfo } from '../core/types'
import { findFiles, readTextOrNull } from '../core/fs'
import { asRecord } from '../core/json'
import { eventsOf } from './claude-code'
import { at, readConfig, serversIn, setupOf } from './setup'
import type { AgentDef, HistoryItem, HistoryOptions } from './types'

const SUPPORT = '~/Library/Application Support/Claude'
const REL = 'Library/Application Support/Claude'

// Cowork writes Claude Agent SDK records (session_id, cwd on the init line); said as Claude Code transcript lines, eventsOf reads them.
export const coworkEvents = (text: string) => {
  let cwd = ''
  const lines = text.split('\n').flatMap((raw) => {
    try {
      const line = asRecord(JSON.parse(raw))
      if (typeof line['cwd'] === 'string') cwd = line['cwd']
      return [JSON.stringify({ ...line, sessionId: line['session_id'], cwd })]
    } catch {
      return []
    }
  })
  return eventsOf(lines.join('\n'))
}

// The Code tab writes Claude Code transcripts, read once under Claude Code; Cowork keeps its own audit.
async function* history(o: HistoryOptions): AsyncIterable<HistoryItem> {
  const dir = join(o.home, REL, 'local-agent-mode-sessions')
  for (const file of await findFiles('**/audit.jsonl', dir, { absolute: true, deep: 6 })) {
    const info = await stat(file).catch(() => null)
    if (!info || (o.since !== undefined && o.now - info.mtimeMs > o.since)) continue
    const events = coworkEvents((await readTextOrNull(file)) ?? '')
    yield { id: events[0]?.event.session_id ?? file, startedBy: 'you', events }
  }
}

// The Claude desktop app: chats live in the account; its Code tab writes Claude Code's records; Cowork keeps a local audit.
export const claudeDesktop: AgentDef = {
  id: 'claude-desktop', name: 'Claude (desktop app)', kind: 'desktop assistant',
  footprint: { apps: ['Claude'], dirs: [SUPPORT], activity: [`${SUPPORT}/claude-code-sessions`, `${SUPPORT}/local-agent-mode-sessions`], processes: ['Claude'] },
  paths: {
    data: [SUPPORT, '~/Library/Logs/Claude'],
    conversations: [`${SUPPORT}/local-agent-mode-sessions`, `${SUPPORT}/claude-code-sessions`],
    configs: [`${SUPPORT}/claude_desktop_config.json`],
    secrets: [`${SUPPORT}/config.json`],
  },
  history,
  setup: async (home) => {
    const configFile = at(home, `${REL}/claude_desktop_config.json`)
    const extensionsFile = at(home, `${REL}/extensions-installations.json`)
    const config = await readConfig(configFile, 'json')
    const installed = await readConfig(extensionsFile, 'json')
    // An installed extension is a packaged tool server; its id ends with the server's name.
    const extensions = Object.keys(asRecord(installed.data?.['extensions'])).map((id): McpServerInfo => ({ name: id.split('.').pop() ?? id, configPath: extensionsFile, transport: 'stdio' }))
    return setupOf({ toolServers: [...serversIn(configFile, config.text, config.data?.['mcpServers']), ...extensions] }, [config, installed])
  },
}
