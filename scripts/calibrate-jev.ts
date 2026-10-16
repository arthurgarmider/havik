// Manual calibration for the AI checks. Needs TYPESAFE_API_KEY, and sends the labelled fixtures below
// (redacted, as in a real scan) to the TypeSafe API: 10 skills x 3 runs. Prints a table; --write stores
// the thresholds and today's date in data/jev-calibration.json. A question whose benign and malicious
// answers are closer than 0.2 stays uncalibrated and reports nothing. The corpus is small (6 benign, 4
// malicious): treat the result as a smoke test and add labelled skills before relying on a threshold.
import { join } from 'node:path'
import { writeFile } from 'node:fs/promises'
import { calibrate, measure, type Labelled } from '../src/ai/calibrate'
import { createJudge } from '../src/ai/client'
import { FAMILIES } from '../src/ai/jev'

const REPEATS = 3
const ROOT = join(import.meta.dir, '..')
const INJECTION = ['injection-overrides', 'injection-conceals', 'injection-sends-data']

// positive: the questions a skill must trigger; skip: questions it may or may not trigger; every other question must stay quiet.
const CORPUS: Labelled[] = [
  ...['careful-email', 'security-guide'].map(n => ({ dir: `tests/fixtures/ai/benign/${n}`, positive: [] })),
  ...['python', 'js', 'api-skill', 'aws-skill/skills/aws-sts'].map(n => ({ dir: `tests/fixtures/benign/${n}`, positive: [] })),
  { dir: 'tests/fixtures/ai/malicious/override', positive: ['injection-overrides'], skip: INJECTION },
  { dir: 'tests/fixtures/ai/malicious/conceal', positive: ['injection-conceals'], skip: INJECTION },
  { dir: 'tests/fixtures/ai/malicious/send', positive: ['injection-sends-data'], skip: INJECTION },
  { dir: 'tests/fixtures/attacks/skill-exfil', positive: ['overreach', 'unneeded-evidence'] },
]

if (!process.env['TYPESAFE_API_KEY']?.trim()) {
  console.error('Set TYPESAFE_API_KEY first. This script sends the labelled fixtures to the TypeSafe API.')
  process.exit(1)
}

const { benign, malicious, skipped } = await measure(CORPUS, createJudge(), ROOT, REPEATS)
if (skipped.length > 0) console.error(`No SKILL.md to read in: ${skipped.join(', ')}`)

const thresholds: Record<string, number | null> = {}
for (const key of [...FAMILIES.map(f => f.key), 'unneeded-evidence']) {
  const result = calibrate(benign.get(key) ?? [], malicious.get(key) ?? [])
  thresholds[key] = result.threshold
  console.log(`${key.padEnd(22)} benign max ${result.benignMax.toFixed(2)}  malicious min ${result.maliciousMin.toFixed(2)}  gap ${result.gap.toFixed(2)}  ->  ${result.threshold ?? 'uncalibrated'}`)
}

const table = { calibratedOn: new Date().toISOString().slice(0, 10), thresholds }
if (process.argv.includes('--write')) await writeFile(join(ROOT, 'data/jev-calibration.json'), `${JSON.stringify(table, null, 2)}\n`)
else console.log(`\n${JSON.stringify(table, null, 2)}\n\nRe-run with --write to store this in data/jev-calibration.json.`)
