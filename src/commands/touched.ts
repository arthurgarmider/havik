import { homedir } from 'node:os'
import { join } from 'node:path'
import { loadSensitivityMap } from '../core/sensitivity'
import { guardMap, loadGuardConfig } from '../guard/policy'
import { replaySessions } from '../guard/replay'
import { formatTouched } from '../guard/touched'

const SPAN = '30d'
const SPAN_MS = 30 * 86_400_000

export const touchedAction = async (): Promise<void> => {
  const dir = join(homedir(), '.claude', 'projects')
  const config = await loadGuardConfig()
  // A heavy user has gigabytes of transcripts; say what the wait is, in a terminal only, and erase it after.
  if (process.stderr.isTTY) process.stderr.write(`havik: reading your Claude Code sessions of the last ${SPAN}…`)
  const result = await replaySessions({ projectsDir: dir, home: homedir(), config, map: guardMap(await loadSensitivityMap(), config), since: SPAN_MS })
  if (process.stderr.isTTY) process.stderr.write('\r\x1b[K')
  process.stdout.write(`${formatTouched(result, SPAN, homedir(), dir)}\n`)
}
