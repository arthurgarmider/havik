import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { detectGeneric, analyzeGeneric } from '../../src/adapters/generic'

const FIXTURES = join(import.meta.dir, '../fixtures/generic')
const withEnv = join(FIXTURES, 'with-env')
const clean = join(FIXTURES, 'clean')

describe('detectGeneric', () => {
  it('always returns true', () => {
    expect(detectGeneric()).toBe(true)
  })
})

describe('analyzeGeneric', () => {
  it('finds .env file with secrets', async () => {
    const result = await analyzeGeneric(withEnv)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const secretFindings = result.value.filter(f => f.ruleId === 'env-secret-exposure')
    expect(secretFindings.length).toBeGreaterThan(0)
    expect(secretFindings[0].severity).toBe('high')
  })

  it('returns empty findings for clean directory', async () => {
    const result = await analyzeGeneric(clean)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.length).toBe(0)
  })

  it('returns ok result structure', async () => {
    const result = await analyzeGeneric(withEnv)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(Array.isArray(result.value)).toBe(true)
  })
})

describe('analyzeGeneric: hidden directories', () => {
  it('finds a bind-all config inside a dot-directory and still skips .ssh and certs keys', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'havik-gen-'))
    try {
      await mkdir(join(dir, '.app'))
      await mkdir(join(dir, '.ssh'))
      await mkdir(join(dir, 'certs'))
      await mkdir(join(dir, 'other'))
      await writeFile(join(dir, '.app/server.json'), '{ "host": "0.0.0.0" }')
      await writeFile(join(dir, '.ssh/id.pem'), 'k')
      await writeFile(join(dir, 'certs/x.pem'), 'k')
      await writeFile(join(dir, 'other/y.pem'), 'k')
      const result = await analyzeGeneric(dir)
      if (!result.ok) throw new Error(result.error)
      const found = result.value.map(f => `${f.ruleId}:${f.proof?.file.slice(dir.length + 1)}`).sort()
      expect(found).toEqual(['bind-all-interfaces:.app/server.json', 'credential-file-exposed:other/y.pem'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
