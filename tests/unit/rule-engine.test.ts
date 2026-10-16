import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { validateRule, loadRules } from '../../src/core/rule-engine'

const FIXTURES = join(import.meta.dir, '../fixtures')

const validRule = {
  id: 'test-capability-mismatch',
  type: 'capability_mismatch',
  severity: 'high',
  confidence: 'high',
  owasp: 'ASI02',
  frameworks: ['openclaw'],
  description: 'Test rule for capability mismatch',
  match: { capability_observed: 'network', capability_not_declared: 'network' },
}

describe('validateRule', () => {
  it('accepts valid capability_mismatch rule', () => {
    const result = validateRule(validRule)
    expect(result.ok).toBe(true)
  })

  it('accepts valid pattern rule', () => {
    const result = validateRule({ ...validRule, id: 'pattern-rule', type: 'pattern' })
    expect(result.ok).toBe(true)
  })

  it('rejects rule with unknown severity', () => {
    const result = validateRule({ ...validRule, severity: 'extreme' })
    expect(result.ok).toBe(false)
  })

  it('rejects rule missing required fields', () => {
    const { description: _, ...incomplete } = validRule
    const result = validateRule(incomplete)
    expect(result.ok).toBe(false)
  })

  it('rejects rule with unknown fields', () => {
    const result = validateRule({ ...validRule, unknown_field: 'should fail' })
    expect(result.ok).toBe(false)
  })
})

describe('loadRules', () => {
  it('loads valid YAML rules from directory', async () => {
    const result = await loadRules(join(FIXTURES, 'rules/valid'))
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.length).toBeGreaterThan(0)
      expect(result.value[0].id).toBe('test-capability-mismatch')
    }
  })

  it('rejects directory with invalid rules', async () => {
    const result = await loadRules(join(FIXTURES, 'rules/invalid'))
    expect(result.ok).toBe(false)
  })
})
