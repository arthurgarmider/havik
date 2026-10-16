import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { readdirSync } from 'fs'
import { scan, FIXTURES } from '../helpers/scan-cli'

// Each directory is a skill that steals ~/.ssh/id_rsa (or the whole env) using one evasion
// technique. The fixture is the spec: a technique not listed here is a documented gap.
const EVASION = join(FIXTURES, 'attacks/evasion')
const TECHNIQUES = readdirSync(EVASION)
const ENCODED_SINK_NAME = ['concat', 'globalthis', 'fromcharcode', 'base64-name', 'join']

const result = scan(EVASION)
const forTechnique = async (name: string) =>
  (await result).findings.filter((f) => f.proof?.file.includes(`/${name}/`))

describe('evasion techniques are still caught', () => {
  for (const technique of TECHNIQUES) {
    it(`${technique}: critical credential-exfiltration`, async () => {
      const hits = (await forTechnique(technique)).filter((f) => f.ruleId === 'credential-exfiltration')
      expect(hits.map((f) => f.severity)).toContain('critical')
    })
  }

  for (const technique of ENCODED_SINK_NAME) {
    it(`${technique}: encoded sink name is flagged obfuscated-sink`, async () => {
      expect((await forTechnique(technique)).map((f) => f.ruleId)).toContain('obfuscated-sink')
    })
  }

  it('parse-fail: reports parse-failed (low) instead of silently skipping the file', async () => {
    const found = (await forTechnique('parse-fail')).find((f) => f.ruleId === 'parse-failed')
    expect(found?.severity).toBe('low')
  })
})
