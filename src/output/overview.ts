import type { AgentOverview, Overview } from '../overview'

// What each agent did in the window, from the replay of its records.
export type Activity = Readonly<Record<string, { readonly sessions: number; readonly toolCalls: number; readonly unknownActions: number }>>

const DAY_MS = 86_400_000
const MAX_LINE = 100
const NAME_WIDTH = 22
const WHEN_WIDTH = 19
const MAX_ROW_LINES = 16
const MAX_COMPACT_LINES = 10
const INDENT = ' '.repeat(2 + NAME_WIDTH + WHEN_WIDTH)

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`

const fit = (text: string): string => (text.length > MAX_LINE ? `${text.slice(0, MAX_LINE - 1)}…` : text)

const whenOf = (a: AgentOverview, now: number): string => {
  if (a.presence.running) return 'running now'
  if (a.presence.lastUsed === undefined) return 'installed'
  const days = Math.floor((now - a.presence.lastUsed) / DAY_MS)
  return days <= 0 ? 'used today' : days === 1 ? 'used yesterday' : `used ${days} days ago`
}

// What it is and what it is connected to, in the words a person uses.
const activityOf = (a: AgentOverview, activity?: Activity): string[] => {
  const did = activity?.[a.def.id]
  if (!did || did.sessions === 0) return []
  const all = did.toolCalls + did.unknownActions
  const understood = did.unknownActions > 0 ? ` (${Math.floor((100 * did.toolCalls) / all)}% understood)` : ''
  const count = (n: number, one: string, many: string) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`
  if (did.toolCalls === 0 && did.unknownActions === 0) return [`${count(did.sessions, 'conversation', 'conversations')}, no actions`]
  return [`${count(did.sessions, 'conversation', 'conversations')} · ${count(did.toolCalls, 'action', 'actions')}${understood}`]
}

const partsOf = (a: AgentOverview, activity?: Activity) => {
  const s = a.setup
  const servers = s?.toolServers ?? []
  const withSecret = servers.filter(t => (t.secrets?.length ?? 0) > 0).length
  return {
    kind: [a.def.kind],
    activity: activityOf(a, activity),
    note: a.def.historyNote ? [a.def.historyNote] : [],
    servers: servers.length > 0 ? [`${plural(servers.length, 'tool server', 'tool servers')}${withSecret > 0 ? ` (${withSecret} ${withSecret === 1 ? 'keeps' : 'keep'} a password in its settings file)` : ''}`] : [],
    alarms: [
      ...(s && s.schedules > 0 ? [`starts itself on ${plural(s.schedules, 'schedule', 'schedules')}`] : []),
      ...(s && s.channels.length > 0 ? [`reachable from ${s.channels.join(', ')}`] : []),
      ...(s?.approvals === 'runs without asking' ? [s.approvals] : []),
    ],
    calm: s?.approvals === 'asks first' ? [s.approvals] : [],
  }
}

const detailsOf = (a: AgentOverview, activity?: Activity): string[] => {
  const p = partsOf(a, activity)
  return [...p.kind, ...p.activity, ...p.note, ...p.servers, ...p.alarms, ...p.calm]
}

// At most two lines per agent for the default screen: what it is, what should worry a person, what it did, then the rest.
const compactRowOf = (a: AgentOverview, now: number, activity?: Activity): string[] => {
  const p = partsOf(a, activity)
  const lines = wrap(`  ${a.def.name.padEnd(NAME_WIDTH)}${whenOf(a, now).padEnd(WHEN_WIDTH)}`, [...p.kind, ...p.alarms, ...p.activity, ...p.note, ...p.servers, ...p.calm])
  return lines.length <= 2 ? lines : [lines[0], fit(`${lines[1]} …`)]
}

// One agent's row, wrapped at a ' · ' so no line passes 100 characters.
const rowOf = (a: AgentOverview, now: number, activity?: Activity): string[] =>
  wrap(`  ${a.def.name.padEnd(NAME_WIDTH)}${whenOf(a, now).padEnd(WHEN_WIDTH)}`, detailsOf(a, activity))

const wrap = (head: string, parts: readonly string[]): string[] => {
  const lines: string[] = []
  let current = head
  let first = true
  for (const part of parts) {
    const joined = first ? `${current}${part}` : `${current} · ${part}`
    if (joined.length > MAX_LINE && !first && current.trim().length > 0) {
      lines.push(current)
      current = `${INDENT}${part}`
    } else {
      current = joined
    }
    first = false
  }
  return [...lines, fit(current)]
}

const wasUsed = (a: AgentOverview): boolean => a.presence.running === true || a.presence.lastUsed !== undefined

// Set up to act: worth its own row even before it was ever used.
const isNotable = (a: AgentOverview): boolean => {
  const s = a.setup
  return !!s && (s.toolServers.length > 0 || s.channels.length > 0 || s.schedules > 0 || s.approvals === 'runs without asking')
}

export const formatAgents = (o: Overview, now: number = Date.now(), activity?: Activity, opts: { compact?: boolean } = {}): string => {
  if (o.agents.length === 0) return 'havik: the AI agents on this computer\nNo AI agents found on this computer.'
  const used = o.agents.filter(a => wasUsed(a) || isNotable(a))
  const unused = o.agents.filter(a => !wasUsed(a) && !isNotable(a))
  const rows: string[] = []
  const shown: AgentOverview[] = []
  for (const a of used) {
    const lines = opts.compact ? compactRowOf(a, now, activity) : rowOf(a, now, activity)
    if (rows.length + lines.length > (opts.compact ? MAX_COMPACT_LINES : MAX_ROW_LINES)) break
    rows.push(...lines)
    shown.push(a)
  }
  const more = used.slice(shown.length)
  return [
    'havik: the AI agents on this computer',
    'Found by looking at this computer only; nothing leaves it.',
    ...(o.processesChecked ? [] : ['havik could not see which programs are running, so none is shown as running now.']),
    '',
    ...rows,
    ...(more.length > 0 ? [fit(`  And ${more.length} more: ${more.map(a => a.def.name).join(', ')}`)] : []),
    ...(unused.length > 0 ? [fit(`  Not used yet: ${unused.map(a => a.def.name).join(', ')}`)] : []),
  ].join('\n')
}
