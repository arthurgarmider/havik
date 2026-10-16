import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { detectCapabilities } from '../../src/core/capability-detector'

const FIXTURES = join(import.meta.dir, '../fixtures')
const MALICIOUS = join(FIXTURES, 'skills/malicious/exfil-skill')
const CALENDAR = join(FIXTURES, 'skills/clean/calendar-skill')

describe('detectCapabilities', () => {
  it('detects network capability from fetch() in malicious skill', async () => {
    const result = await detectCapabilities(MALICIOUS)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.observed.has('network')).toBe(true)
  })

  it('detects credentials capability from process.env in malicious skill', async () => {
    const result = await detectCapabilities(MALICIOUS)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.observed.has('credentials')).toBe(true)
  })

  it('detects filesystem.read from readFileSync in malicious skill', async () => {
    const result = await detectCapabilities(MALICIOUS)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.observed.has('filesystem.read')).toBe(true)
  })

  it('does NOT detect network in clean calendar skill', async () => {
    const result = await detectCapabilities(CALENDAR)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.observed.has('network')).toBe(false)
  })

  it('detects filesystem.read AND filesystem.write in calendar skill', async () => {
    const result = await detectCapabilities(CALENDAR)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.observed.has('filesystem.read')).toBe(true)
    expect(result.value.observed.has('filesystem.write')).toBe(true)
  })

  it('returns undeclared capabilities when declared set is provided', async () => {
    const declared = new Set<import('../../src/core/types').Capability>(['filesystem.read'])
    const result = await detectCapabilities(MALICIOUS, declared)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.undeclared.has('network')).toBe(true)
    expect(result.value.undeclared.has('credentials')).toBe(true)
    expect(result.value.undeclared.has('filesystem.read')).toBe(false)
  })

  it('returns empty observed set for directory with no source files', async () => {
    const result = await detectCapabilities(join(FIXTURES, 'rules'))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.observed.size).toBe(0)
  })

  it('reports only what plain JS does, not substrings of words like exec(, http, forgot, internet', async () => {
    const result = await detectCapabilities(join(FIXTURES, 'benign/js'))
    if (!result.ok) throw new Error(result.error)
    expect([...result.value.observed]).toEqual(['network'])
  })

  it('sees capabilities in modern JS that the old substring signatures missed', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'havik-js-'))
    try {
      await writeFile(join(dir, 'a.mjs'), "import { readFile } from 'node:fs/promises'\nconst { exec: run } = await import('node:child_process')\nawait readFile('x')\nrun('ls')\nglobalThis.fetch?.('https://x.example')\n")
      const result = await detectCapabilities(dir)
      if (!result.ok) throw new Error(result.error)
      expect([...result.value.observed].sort()).toEqual(['filesystem.read', 'network', 'shell'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('reports nothing for plain python that only contains os-like words and comments', async () => {
    const result = await detectCapabilities(join(FIXTURES, 'benign/python'))
    if (!result.ok) throw new Error(result.error)
    expect([...result.value.observed]).toEqual([])
  })

  it('still reports python capabilities from real imports and calls', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'havik-py-'))
    try {
      await writeFile(join(dir, 'a.py'), "import subprocess\nsubprocess.run(['ls'])\nrequests.post('http://x', data=1)\nfrom dotenv import load_dotenv\nopen('f')\n")
      const result = await detectCapabilities(dir)
      if (!result.ok) throw new Error(result.error)
      expect([...result.value.observed].sort()).toEqual(['credentials', 'filesystem.read', 'network', 'shell'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
