import { trace } from './trace'
import type { Finding, Grade, PostureScore, Severity } from './types'

const WEIGHTS: Record<Severity, number> = { critical: 40, high: 20, medium: 10, low: 2 }
const MAX_PENALTY = 100

function toGrade(percentage: number): Grade {
  if (percentage >= 90) return 'A'
  if (percentage >= 75) return 'B'
  if (percentage >= 55) return 'C'
  if (percentage >= 35) return 'D'
  return 'F'
}

export const calculateScore = trace(
  'calculateScore',
  (findings: readonly Finding[]): PostureScore => {
    const findingCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    const owaspCoverage: Record<string, number> = {}
    let totalPenalty = 0

    for (const f of findings) {
      findingCounts[f.severity]++
      owaspCoverage[f.owasp] = (owaspCoverage[f.owasp] ?? 0) + 1
      totalPenalty += WEIGHTS[f.severity]
    }

    const percentage = Math.max(0, Math.round(100 - totalPenalty))

    return { grade: toGrade(percentage), percentage, findingCounts, owaspCoverage }
  }
)
