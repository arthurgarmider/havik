import { describe, it, expect } from 'bun:test'
import type { Finding, Rule } from '../../src/core/types'

describe('types', () => {
  it('Finding satisfies the shape contract', () => {
    const finding: Finding = {
      id: 'SK-001',
      ruleId: 'undeclared-network-access',
      severity: 'critical',
      confidence: 'high',
      owasp: 'ASI02',
      description: 'Test finding',
    }
    expect(finding.severity).toBe('critical')
    expect(finding.confidence).toBe('high')
  })

  it('Rule supports both types', () => {
    const mismatch: Rule = {
      id: 'test-mismatch',
      type: 'capability_mismatch',
      severity: 'high',
      confidence: 'high',
      owasp: 'ASI02',
      frameworks: ['openclaw'],
      description: 'Test',
      match: { capability_observed: 'network', capability_not_declared: 'network' },
    }
    const pattern: Rule = {
      id: 'test-pattern',
      type: 'pattern',
      severity: 'critical',
      confidence: 'high',
      owasp: 'ASI04',
      frameworks: ['openclaw'],
      description: 'Test',
      match: { file_contains: 'eval\\(' },
    }
    expect(mismatch.type).toBe('capability_mismatch')
    expect(pattern.type).toBe('pattern')
  })
})
