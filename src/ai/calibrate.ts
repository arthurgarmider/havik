import { join } from 'node:path'
import { briefFor } from './briefs'
import { FAMILIES, askJev, type Judge } from './jev'
import { UNNEEDED } from './questions'

// A question may only report findings once its answers separate benign skills from malicious ones.
// The threshold is the middle of the gap between the highest benign answer and the lowest malicious one;
// a gap under MIN_GAP means the question cannot tell them apart and stays uncalibrated (null).
export const MIN_GAP = 0.2

export interface Calibration { readonly threshold: number | null; readonly gap: number; readonly benignMax: number; readonly maliciousMin: number }

const round = (n: number): number => Math.round(n * 100) / 100

export const calibrate = (benign: readonly number[], malicious: readonly number[]): Calibration => {
  const benignMax = benign.length > 0 ? Math.max(...benign) : Number.NaN
  const maliciousMin = malicious.length > 0 ? Math.min(...malicious) : Number.NaN
  const gap = round(maliciousMin - benignMax)
  return { threshold: gap >= MIN_GAP ? round((benignMax + maliciousMin) / 2) : null, gap, benignMax, maliciousMin }
}

// A labelled skill: the questions it must trigger (positive) and the ones whose answer is not held against it (skip).
export interface Labelled { readonly dir: string; readonly positive: readonly string[]; readonly skip?: readonly string[] }

const keyOf = (answer: string): string => (answer.startsWith('unneeded_') ? UNNEEDED.key : FAMILIES.find(f => f.name === answer)?.key ?? answer)

// Asks Jev about every labelled skill `repeats` times and files each answer under its question and label.
// Skills get neutral names, so a directory name cannot carry the label into the prompt.
export async function measure(corpus: readonly Labelled[], judge: Judge, root: string, repeats = 3) {
  const benign = new Map<string, number[]>()
  const malicious = new Map<string, number[]>()
  const skipped: string[] = []
  for (const [i, { dir, positive, skip = [] }] of corpus.entries()) {
    const brief = await briefFor({ name: `skill-${i + 1}`, dir: join(root, dir) })
    if (!brief) {
      skipped.push(dir)
      continue
    }
    for (let run = 0; run < repeats; run++) {
      for (const [answer, value] of Object.entries((await askJev(judge, brief)).answers)) {
        const key = keyOf(answer)
        const side = positive.includes(key) ? malicious : skip.includes(key) ? undefined : benign
        if (side && typeof value?.noul === 'number') side.set(key, [...(side.get(key) ?? []), value.noul])
      }
    }
  }
  return { benign, malicious, skipped }
}
