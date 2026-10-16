import { describe, it, expect } from 'bun:test'
import { calculateScore } from '../../src/core/scoring'
import type { Finding } from '../../src/core/types'

const makeFinding = (overrides: Partial<Finding>): Finding => ({
  id: 'f1',
  ruleId: 'r1',
  severity: 'low',
  confidence: 'high',
  owasp: 'A01',
  description: 'test',
  ...overrides,
})

describe('calculateScore', () => {
  it('returns grade A and 100% for no findings', () => {
    const score = calculateScore([])
    expect(score.grade).toBe('A')
    expect(score.percentage).toBe(100)
  })

  it('returns grade F for 2 critical findings', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical' }),
      makeFinding({ id: 'f2', severity: 'critical' }),
    ]
    const score = calculateScore(findings)
    expect(score.grade).toBe('F')
  })

  it('counts findings by severity correctly', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical' }),
      makeFinding({ id: 'f2', severity: 'high' }),
      makeFinding({ id: 'f3', severity: 'high' }),
      makeFinding({ id: 'f4', severity: 'low' }),
    ]
    const { findingCounts } = calculateScore(findings)
    expect(findingCounts.critical).toBe(1)
    expect(findingCounts.high).toBe(2)
    expect(findingCounts.medium).toBe(0)
    expect(findingCounts.low).toBe(1)
  })

  it('maps findings to OWASP categories', () => {
    const findings = [
      makeFinding({ id: 'f1', owasp: 'A01' }),
      makeFinding({ id: 'f2', owasp: 'A01' }),
      makeFinding({ id: 'f3', owasp: 'A02' }),
    ]
    const { owaspCoverage } = calculateScore(findings)
    expect(owaspCoverage['A01']).toBe(2)
    expect(owaspCoverage['A02']).toBe(1)
  })

  it('percentage never goes below 0', () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding({ id: `f${i}`, severity: 'critical' })
    )
    const { percentage } = calculateScore(findings)
    expect(percentage).toBe(0)
  })
})
