import { redactSecrets } from '../core/redact'
import { trace } from '../core/trace'
import type { SkillTarget } from '../core/skill-analyzer'
import type { Finding } from '../core/types'
import { briefFor } from './briefs'
import { judgeSkill, type Judge, type Thresholds } from './jev'

// One request per skill, so a run over a whole home directory stays bounded.
const MAX_SKILLS = 50

// Text from the API, or from a directory name, is printed on one plain line: no secrets, no control characters.
const plain = (text: unknown, max: number): string => redactSecrets(text instanceof Error ? text.message : String(text)).replace(/\p{Cc}/gu, ' ').slice(0, max)

// Asks Jev about each skill. A failure ends the AI part with one warning; the static findings are never affected.
export const runAi = trace('runAi', async (targets: readonly SkillTarget[], judge: Judge, thresholds: Thresholds): Promise<{ findings: Finding[]; warnings: string[] }> => {
  const findings: Finding[] = []
  const warnings: string[] = []
  const uncalibrated = new Set<string>()
  const incomplete: string[] = []
  const chosen = targets.slice(0, MAX_SKILLS)
  if (chosen.length < targets.length) warnings.push(`AI checks ran on the first ${MAX_SKILLS} of ${targets.length} skills`)

  for (const target of chosen) {
    try {
      const brief = await briefFor(target)
      if (!brief) continue
      const verdict = await judgeSkill(judge, brief, thresholds)
      findings.push(...verdict.findings)
      verdict.uncalibrated.forEach(key => uncalibrated.add(key))
      if (verdict.unanswered.length > 0 || verdict.shortened) incomplete.push(plain(target.name, 60))
    } catch (error) {
      warnings.push(`AI checks stopped at skill ${plain(target.name, 60)}: ${plain(error, 200)}`)
      break
    }
  }
  if (incomplete.length > 0) {
    const named = incomplete.slice(0, 5).join(', ') + (incomplete.length > 5 ? ` and ${incomplete.length - 5} more` : '')
    warnings.push(`AI checks were incomplete for ${named}: Jev left some questions unanswered or the request had to be shortened`)
  }
  if (uncalibrated.size > 0) {
    warnings.push(`AI answers were not reported for ${[...uncalibrated].sort().join(', ')}: those questions are not calibrated yet (scripts/calibrate-jev.ts)`)
  }
  return { findings, warnings }
})
