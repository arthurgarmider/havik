import { join } from 'node:path'
import * as yaml from 'js-yaml'
import { parse as parseToml } from 'smol-toml'
import { parseMcpServers } from '../adapters/mcp'
import { hostOf } from '../core/exfil-patterns'
import { readTextOrNull } from '../core/fs'
import { asRecord } from '../core/json'
import type { McpServerInfo } from '../core/types'
import type { AgentSetup } from './types'

// Shared by the agents' setup readers. A missing file is "not set up"; a file that does not parse is a warning.
export interface Parsed { readonly data?: Record<string, any>; readonly text: string; readonly warning?: string }

type Format = 'json' | 'yaml' | 'toml'
const PARSERS: Record<Format, (text: string) => unknown> = { json: JSON.parse, yaml: yaml.load, toml: parseToml }

export const readConfig = async (path: string, format: Format): Promise<Parsed> => {
  const text = await readTextOrNull(path)
  if (text === null || text.trim() === '') return { text: '' }
  try {
    return { data: asRecord(PARSERS[format](text)), text }
  } catch {
    return { text, warning: `could not read ${path}` }
  }
}

// Only what the overview shows: the name, how it is reached, a remote host, and which keys hold a secret. No command, argument or value.
export const serversIn = (path: string, text: string, entries: unknown): McpServerInfo[] =>
  parseMcpServers(path, text, entries).map(s => ({ name: s.name, configPath: s.configPath, transport: s.transport, url: s.url ? hostOf(s.url) : undefined, secrets: s.secrets }))

const CHANNELS: Record<string, string> = { telegram: 'Telegram', slack: 'Slack', discord: 'Discord', whatsapp: 'WhatsApp', signal: 'Signal', imessage: 'iMessage', matrix: 'Matrix', email: 'email', teams: 'Microsoft Teams' }
export const channelName = (id: string): string | undefined => CHANNELS[id.toLowerCase()]

export const setupOf = (parts: Partial<AgentSetup>, parsed: readonly Parsed[]): AgentSetup => {
  const byName = new Map((parts.toolServers ?? []).map(s => [s.name, s]))
  return {
    toolServers: [...byName.values()].sort((a, b) => a.name.localeCompare(b.name)),
    channels: [...new Set(parts.channels ?? [])].sort(),
    schedules: parts.schedules ?? 0,
    ...(parts.approvals ? { approvals: parts.approvals } : {}),
    warnings: [...(parts.warnings ?? []), ...parsed.flatMap(p => (p.warning ? [p.warning] : []))],
  }
}

export const at = (home: string, rel: string): string => join(home, rel)
