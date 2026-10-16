import type { Finding } from './types'

const keyOf = (f: Finding): string => [f.ruleId, f.proof?.file, f.proof?.line, f.description].join('\0')

// The same install can be reached from two scan roots (-r), and every adapter numbers its own ids,
// so each finding is reported once and ids are unique across the whole result.
export const dedupeAndRenumber = (findings: readonly Finding[]): Finding[] => {
  const seen = new Set<string>()
  const counters = new Map<string, number>()
  const out: Finding[] = []
  for (const f of findings) {
    const key = keyOf(f)
    if (seen.has(key)) continue
    seen.add(key)
    const prefix = f.id.replace(/-\d+$/, '')
    const n = (counters.get(prefix) ?? 0) + 1
    counters.set(prefix, n)
    out.push({ ...f, id: `${prefix}-${String(n).padStart(3, '0')}` })
  }
  return out
}
