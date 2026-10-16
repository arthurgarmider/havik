import { homedir } from 'node:os'
import { machine } from '../agents/presence'
import { agentById } from '../agents/registry'
import { loadSensitivityMap } from '../core/sensitivity'
import { guardMap, loadGuardConfig } from '../guard/policy'
import { replayAgents } from '../guard/replay'
import { formatTouched } from '../guard/touched'
import { buildOverview } from '../overview'
import { formatAgents } from '../output/overview'

const SPAN = '30d'
const SPAN_MS = 30 * 86_400_000

// The default screen: the agents on this computer, then what they did in the last 30 days, from their own records.
export const touchedAction = async (): Promise<void> => {
  const home = homedir()
  const config = await loadGuardConfig()
  const overview = await buildOverview(await machine())
  const readable = overview.agents.map(a => a.def).filter(def => def.history)
  // A heavy user has gigabytes of records; say what the wait is, in a terminal only, and erase it after.
  if (process.stderr.isTTY) process.stderr.write(`havik: reading the records of ${readable.map(d => d.name).join(', ')} for the last ${SPAN}…`)
  const result = await replayAgents({ home, config, map: guardMap(await loadSensitivityMap(), config), since: SPAN_MS, agents: readable })
  if (process.stderr.isTTY) process.stderr.write('\r\x1b[K')
  const names = (id: string) => agentById(id)?.name ?? id
  process.stdout.write(`${formatAgents(overview, Date.now(), result.agents, { compact: true })}\n\n${formatTouched(result, SPAN, home, undefined, names)}\n`)
  for (const w of [...overview.warnings, ...result.warnings]) process.stderr.write(`warning: ${w}\n`)
}
