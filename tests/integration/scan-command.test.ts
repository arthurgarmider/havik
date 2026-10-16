import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { scan } from '../helpers/scan-cli'

const COMPROMISED = join(import.meta.dir, '../fixtures/openclaw/compromised')
const HARDENED = join(import.meta.dir, '../fixtures/openclaw/hardened')

describe('havik scan', () => {
  it('produces findings for compromised fixture', async () => {
    const result = (await scan(COMPROMISED)).json
    expect(result.findings.length).toBeGreaterThan(0)
  })

  it('produces clean scan for hardened fixture', async () => {
    const result = (await scan(HARDENED)).json
    expect(result.findings.length).toBe(0)
    expect(result.score.grade).toBe('A')
  })

  it('respects --severity filter', async () => {
    const result = (await scan(COMPROMISED, '--severity', 'critical')).json
    for (const f of result.findings) {
      expect(f.severity).toBe('critical')
    }
  })

  it('grades and exits on all findings even when --severity hides them', async () => {
    const r = await scan(COMPROMISED, '--severity', 'low')
    for (const f of r.findings) expect(f.severity).toBe('low')
    expect(r.grade).not.toBe('A')
    expect(r.code).toBe(2)
  })

  it('exits 3 with a message instead of grading a path that does not exist', async () => {
    const r = await scan(join(import.meta.dir, '../fixtures/does-not-exist'))
    expect(r.code).toBe(3)
    expect(r.stdout).toBe('')
    expect(r.stderr).toContain('does not exist')
  })

  it('completes in under 10 seconds', async () => {
    const start = Date.now()
    await scan(COMPROMISED)
    expect(Date.now() - start).toBeLessThan(10_000)
  })
})
