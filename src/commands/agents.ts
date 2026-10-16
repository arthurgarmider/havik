import { Command } from 'commander'
import { homedir } from 'node:os'
import { machine } from '../agents/presence'
import type { AgentDef } from '../agents/types'
import { buildOverview, type Overview } from '../overview'
import { formatAgents } from '../output/overview'

// The JSON form keeps the same reduced facts as the screen: names, never a value from a settings file.
export const overviewJson = (o: Overview) => ({
  processesChecked: o.processesChecked,
  warnings: o.warnings,
  agents: o.agents.map(a => ({
    id: a.def.id, name: a.def.name, kind: a.def.kind,
    running: a.presence.running, lastUsed: a.presence.lastUsed ? new Date(a.presence.lastUsed).toISOString() : undefined,
    installed: a.presence.installed, runningToolServers: a.presence.toolServers, note: a.def.historyNote,
    toolServers: (a.setup?.toolServers ?? []).map(t => ({ name: t.name, transport: t.transport, host: t.url, secretKeys: (t.secrets ?? []).map(s => s.key) })),
    channels: a.setup?.channels ?? [], schedules: a.setup?.schedules ?? 0, approvals: a.setup?.approvals,
  })),
})

const TOOLS_SPAN_MS = 30 * 86_400_000

// For each agent with records: how many of its actions havik could not translate, and their tool names (never their arguments).
export const unknownTools = async (agents: readonly AgentDef[], home: string, now: number): Promise<string[]> => {
  const lines: string[] = []
  for (const def of agents) {
    if (!def.history) continue
    let actions = 0
    const unknown = new Map<string, number>()
    for await (const item of def.history({ home, since: TOOLS_SPAN_MS, now })) {
      if ('warning' in item) {
        lines.push(`  ${def.name}: ${item.warning}`)
        continue
      }
      actions += item.events.filter(e => e.event.hook_event_name === 'PreToolUse' && now - e.at <= TOOLS_SPAN_MS).length
      for (const [name, n] of Object.entries(item.unknown ?? {})) unknown.set(name, (unknown.get(name) ?? 0) + n)
    }
    const missed = [...unknown.values()].reduce((a, b) => a + b, 0)
    if (actions + missed === 0) continue
    lines.push(missed === 0
      ? `  ${def.name}: all ${actions} actions understood`
      : `  ${def.name}: ${missed} of ${actions + missed} actions not understood: ${[...unknown].sort((a, b) => b[1] - a[1]).map(([n, k]) => `${n} (${k})`).join(', ')}`)
  }
  return lines
}

export const agentsCommand = new Command('agents')
  .description('The AI agents on this computer: which are installed or running, and what they are connected to (nothing is sent)')
  .option('--json', 'machine-readable output', false)
  .option('--tools', 'the tool names havik does not understand yet, per agent, in the last 30 days', false)
  .action(async (opts: { json: boolean; tools: boolean }) => {
    const overview = await buildOverview(await machine())
    if (opts.tools) {
      const lines = await unknownTools(overview.agents.map(a => a.def), homedir(), Date.now())
      process.stdout.write(`${['Actions havik could not translate, last 30 days (tool names only):', ...(lines.length ? lines : ['  none: no agent records in the last 30 days'])].join('\n')}\n`)
      return
    }
    process.stdout.write(`${opts.json ? JSON.stringify(overviewJson(overview), null, 2) : formatAgents(overview)}\n`)
    for (const w of opts.json ? [] : overview.warnings) process.stderr.write(`warning: ${w}\n`)
    if (overview.warnings.length > 0) process.exitCode = 3
  })
