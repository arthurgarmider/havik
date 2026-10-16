import { presenceOf, type Machine, type Presence } from './agents/presence'
import { AGENTS } from './agents/registry'
import type { AgentDef, AgentSetup } from './agents/types'

// Which agents are on this computer and what they are connected to. Feeds the default screen, `havik agents` and the report.
export interface AgentOverview { readonly def: AgentDef; readonly presence: Presence; readonly setup?: AgentSetup }
export interface Overview { readonly agents: readonly AgentOverview[]; readonly processesChecked: boolean; readonly warnings: readonly string[] }

const isHere = (p: Presence): boolean => p.installed.length > 0 || p.running === true

// Running first, then the most recently used, then by name.
const byActivity = (a: AgentOverview, b: AgentOverview): number =>
  Number(b.presence.running === true) - Number(a.presence.running === true)
  || (b.presence.lastUsed ?? 0) - (a.presence.lastUsed ?? 0)
  || a.def.name.localeCompare(b.def.name)

const setupOf = async (def: AgentDef, home: string): Promise<AgentSetup | undefined> => {
  if (!def.setup) return undefined
  try {
    return await def.setup(home)
  } catch (e) {
    return { toolServers: [], channels: [], schedules: 0, warnings: [`could not read its settings: ${e instanceof Error ? e.message : String(e)}`] }
  }
}

export const buildOverview = async (m: Machine, o: { agents?: readonly AgentDef[]; now?: number } = {}): Promise<Overview> => {
  const agents = o.agents ?? AGENTS
  const all = await Promise.all(agents.map(async def => ({ def, presence: await presenceOf(def, m, agents) })))
  const here = await Promise.all(all.filter(a => isHere(a.presence)).map(async a => ({ ...a, setup: await setupOf(a.def, m.home) })))
  return {
    agents: [...here].sort(byActivity),
    processesChecked: m.processes.ok,
    warnings: [...(m.processes.ok ? [] : [m.processes.error]), ...here.flatMap(a => (a.setup?.warnings ?? []).map(w => `${a.def.name}: ${w}`))],
  }
}
