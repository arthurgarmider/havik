import { agentById } from '../agents/registry'
import { formatTouched } from '../guard/touched'
import { formatAgents } from '../output/overview'
import { collect } from './collect'

// The default screen: the agents on this computer, then what they did in the last 30 days, from their own records.
export const touchedAction = async (): Promise<void> => {
  const { overview, result, home } = await collect()
  const names = (id: string) => agentById(id)?.name ?? id
  // Settings and records of one agent can fail for the same reason: say it once, on the screen.
  const warnings = [...new Set([...overview.warnings, ...result.warnings])]
  process.stdout.write(`${formatAgents(overview, Date.now(), result.agents, { compact: true })}\n\n${formatTouched({ ...result, warnings }, '30d', home, undefined, names)}\n`)
}
