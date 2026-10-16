import { homedir } from 'node:os'
import { machine } from '../agents/presence'
import { loadSensitivityMap } from '../core/sensitivity'
import { guardMap, loadGuardConfig } from '../guard/policy'
import { replayAgents, type ReplayResult } from '../guard/replay'
import { buildOverview, type Overview } from '../overview'

export const SPAN_MS = 30 * 86_400_000

// What the default screen and the report show: the agents here, and the replay of every agent with records.
export const collect = async (): Promise<{ overview: Overview; result: ReplayResult; home: string }> => {
  const home = homedir()
  const config = await loadGuardConfig()
  const overview = await buildOverview(await machine())
  const readable = overview.agents.map(a => a.def).filter(def => def.history)
  // A heavy user has gigabytes of records; say what the wait is, in a terminal only, and erase it after.
  if (process.stderr.isTTY) process.stderr.write(`havik: reading the records of ${readable.map(d => d.name).join(', ')}…`)
  const result = await replayAgents({ home, config, map: guardMap(await loadSensitivityMap(), config), since: SPAN_MS, agents: readable })
  if (process.stderr.isTTY) process.stderr.write('\r\x1b[K')
  return { overview, result, home }
}
