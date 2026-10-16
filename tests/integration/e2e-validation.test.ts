import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { scan } from '../helpers/scan-cli'

const COMPROMISED = join(import.meta.dir, '../fixtures/openclaw/compromised')
const HARDENED = join(import.meta.dir, '../fixtures/openclaw/hardened')
const TYPICAL = join(import.meta.dir, '../fixtures/openclaw/typical')

const runScan = async (path: string, ...args: string[]): Promise<any> => (await scan(path, ...args)).json

describe('V1 Done Criteria', () => {
  // Criterion 1: Detects top 5 real-world issues
  it('detects malicious/exfiltrating skills', async () => {
    const result = await runScan(COMPROMISED)
    const hasCapabilityMismatch = result.findings.some(
      (f: any) => f.ruleId?.includes('undeclared') || f.ruleId?.includes('capability')
    )
    expect(hasCapabilityMismatch).toBe(true)
  })

  it('detects exposed bind address', async () => {
    const result = await runScan(TYPICAL)
    const hasExposed = result.findings.some(
      (f: any) => f.id?.startsWith('EX') || f.description?.includes('0.0.0.0')
    )
    expect(hasExposed).toBe(true)
  })

  it('detects skills with undeclared capabilities', async () => {
    const result = await runScan(COMPROMISED)
    const hasUndeclared = result.findings.some(
      (f: any) => f.severity === 'critical' || f.severity === 'high'
    )
    expect(hasUndeclared).toBe(true)
  })

  // Criterion 2: Deterministic output
  it('produces identical output on consecutive runs', async () => {
    const run1 = await runScan(COMPROMISED)
    const run2 = await runScan(COMPROMISED)
    expect(run1.findings.length).toBe(run2.findings.length)
    expect(run1.score.grade).toBe(run2.score.grade)
    expect(run1.score.percentage).toBe(run2.score.percentage)
  })

  // Criterion 4: Under 10 seconds
  it('completes scan in under 10 seconds', async () => {
    const start = Date.now()
    await runScan(COMPROMISED)
    const duration = Date.now() - start
    expect(duration).toBeLessThan(10_000)
  })

  // Criterion 5: Zero false positives on clean corpus
  it('produces zero findings on hardened fixture', async () => {
    const result = await runScan(HARDENED)
    expect(result.findings.length).toBe(0)
    expect(result.score.grade).toBe('A')
  })

  // Bonus: Score makes sense
  it('compromised fixture gets D or F grade', async () => {
    const result = await runScan(COMPROMISED)
    expect(['D', 'F']).toContain(result.score.grade)
  })

  it('scan includes inventory counts', async () => {
    const result = await runScan(TYPICAL)
    expect(result.inventory).toBeDefined()
    expect(result.inventory.skills.length).toBeGreaterThan(0)
  })
})
