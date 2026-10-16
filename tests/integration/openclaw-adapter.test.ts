import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { detectOpenClaw, discoverOpenClaw, analyzeOpenClaw } from '../../src/adapters/openclaw'

const FIXTURES = join(import.meta.dir, '../fixtures/openclaw')
const typical = join(FIXTURES, 'typical')
const compromised = join(FIXTURES, 'compromised')
const hardened = join(FIXTURES, 'hardened')

describe('detectOpenClaw', () => {
  it('returns true when config.yaml exists', async () => {
    const result = await detectOpenClaw(typical)
    expect(result).toBe(true)
  })

  it('returns false when config.yaml is absent', async () => {
    const result = await detectOpenClaw('/tmp/nonexistent-openclaw-dir')
    expect(result).toBe(false)
  })
})

describe('discoverOpenClaw', () => {
  it('finds skills in typical fixture', async () => {
    const result = await discoverOpenClaw(typical)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.skills.length).toBe(1)
    expect(result.value.skills[0].name).toBe('calendar-sync')
  })

  it('extracts bind_address from config', async () => {
    const result = await discoverOpenClaw(typical)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.agents[0].bindAddress).toBe('0.0.0.0')
    expect(result.value.agents[0].port).toBe(18789)
  })

  it('parses permissions from SKILL.md', async () => {
    const result = await discoverOpenClaw(typical)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const skill = result.value.skills[0]
    expect(skill.manifest?.['declared']).toContain('filesystem.read')
    expect(skill.manifest?.['declared']).toContain('filesystem.write')
  })

  it('includes source files in skill info', async () => {
    const result = await discoverOpenClaw(typical)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.skills[0].sourceFiles.length).toBeGreaterThan(0)
  })

  it('returns error for missing basePath', async () => {
    const result = await discoverOpenClaw('/tmp/nonexistent-path-xyz')
    expect(result.ok).toBe(false)
  })
})

describe('analyzeOpenClaw', () => {
  it('finds exposed bind address on typical fixture', async () => {
    const inv = await discoverOpenClaw(typical)
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const result = await analyzeOpenClaw(inv.value, [])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const exposedFindings = result.value.filter(f => f.ruleId === 'exposed-bind-address')
    expect(exposedFindings.length).toBe(1)
    expect(exposedFindings[0].severity).toBe('critical')
  })

  it('finds undeclared capabilities on compromised fixture', async () => {
    const inv = await discoverOpenClaw(compromised)
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const result = await analyzeOpenClaw(inv.value, [])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const capFindings = result.value.filter(f => f.ruleId === 'undeclared-capability-mismatch')
    expect(capFindings.length).toBeGreaterThan(0)
  })

  it('reports the network+credentials mismatch as high and the exfiltration itself as the one critical', async () => {
    const inv = await discoverOpenClaw(compromised)
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const result = await analyzeOpenClaw(inv.value, [])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const skillFindings = result.value.filter(f => f.ruleId !== 'exposed-bind-address').map(f => `${f.ruleId}:${f.severity}`)
    expect(skillFindings).toContain('undeclared-capability-mismatch:high')
    expect(skillFindings.filter(f => f.endsWith(':critical'))).toEqual(['credential-exfiltration:critical'])
  })

  it('produces zero capability findings on hardened fixture', async () => {
    const inv = await discoverOpenClaw(hardened)
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const result = await analyzeOpenClaw(inv.value, [])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const capFindings = result.value.filter(f => f.ruleId === 'undeclared-capability-mismatch')
    expect(capFindings.length).toBe(0)
  })

  it('hardened fixture has no exposed bind address finding', async () => {
    const inv = await discoverOpenClaw(hardened)
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const result = await analyzeOpenClaw(inv.value, [])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const exposedFindings = result.value.filter(f => f.ruleId === 'exposed-bind-address')
    expect(exposedFindings.length).toBe(0)
  })

  it('includes proof with file and snippet', async () => {
    const inv = await discoverOpenClaw(typical)
    expect(inv.ok).toBe(true)
    if (!inv.ok) return
    const result = await analyzeOpenClaw(inv.value, [])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const withProof = result.value.filter(f => f.proof !== undefined)
    expect(withProof.length).toBeGreaterThan(0)
    expect(withProof[0].proof?.file).toBeTruthy()
    expect(withProof[0].proof?.snippet).toBeTruthy()
  })
})
