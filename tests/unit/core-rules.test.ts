import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { loadRules } from '../../src/core/rule-engine'

const RULES_DIR = join(import.meta.dir, '../../rules/core')

describe('core rules', () => {
  it('ships only the four pattern rules the skill analyzer actually evaluates', async () => {
    const result = await loadRules(RULES_DIR)
    if (!result.ok) throw new Error(result.error)
    expect(result.value.map(r => r.id).sort()).toEqual([
      'dan-style-jailbreak',
      'injection-in-skill-description',
      'remote-fetch-and-execute',
      'suspicious-obfuscation',
    ])
  })

  it('every rule is a pattern rule that applies to all frameworks', async () => {
    const result = await loadRules(RULES_DIR)
    if (!result.ok) throw new Error(result.error)
    for (const rule of result.value) {
      expect(rule.type).toBe('pattern')
      expect(rule.frameworks).toEqual(['all'])
    }
  })

  it('every rule has a unique id', async () => {
    const result = await loadRules(RULES_DIR)
    if (!result.ok) throw new Error(result.error)
    const ids = result.value.map(r => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('every rule maps to an OWASP category', async () => {
    const result = await loadRules(RULES_DIR)
    if (!result.ok) throw new Error(result.error)
    for (const rule of result.value) {
      expect(rule.owasp).toMatch(/^ASI\d{2}$/)
    }
  })
})
