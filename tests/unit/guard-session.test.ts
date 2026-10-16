import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { mkdtemp, readFile, rm, stat, utimes, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { appendLine, applyLine, auditDir, emptyMemory, pruneAudit, readMemory, sessionFile } from '../../src/guard/session'
import type { AuditLine } from '../../src/guard/types'

let home: string
const saved = process.env.HAVIK_HOME
beforeEach(async () => { home = await mkdtemp(join(tmpdir(), 'havik-guard-')); process.env.HAVIK_HOME = home })
afterEach(async () => {
  if (saved === undefined) delete process.env.HAVIK_HOME
  else process.env.HAVIK_HOME = saved
  await rm(home, { recursive: true, force: true })
})

const line = (over: Partial<AuditLine>): AuditLine => ({ ts: '2026-10-15T10:00:00.000Z', session_id: 's1', event: 'access', ms: 3, ...over })
const lines = async (id = 's1') => (await readFile(sessionFile(id), 'utf8')).trim().split('\n').map((l) => JSON.parse(l))

describe('appendLine', () => {
  it('appends one parseable line per call, in a private directory and file', async () => {
    await appendLine(line({ path: '/a' }))
    await appendLine(line({ path: '/b' }))
    expect((await lines()).map((l) => l.path)).toEqual(['/a', '/b'])
    expect((await stat(auditDir())).mode & 0o777).toBe(0o700)
    expect((await stat(sessionFile('s1'))).mode & 0o777).toBe(0o600)
  })

  it('keeps every line under 4 KB, shrinking or replacing an oversized one', async () => {
    await appendLine(line({ event: 'finding', snippet: 'x'.repeat(5000), path: '/p'.repeat(3000) }))
    const raw = await readFile(sessionFile('s1'), 'utf8')
    expect(raw.length).toBeLessThan(4096)
    expect(JSON.parse(raw).event).toMatch(/finding|guard-error/)
  })

  it('parallel appends keep lines whole', async () => {
    await Promise.all(Array.from({ length: 200 }, (_, i) => appendLine(line({ path: `/p/${i}`, snippet: 'y'.repeat(1500) }))))
    const all = await lines()
    expect(all.length).toBe(200)
    expect(new Set(all.map((l) => l.path)).size).toBe(200)
  })

  it('turns a session id into a safe file name', () => {
    expect(sessionFile('../../etc/passwd').startsWith(auditDir())).toBe(true)
    expect(sessionFile('../../etc/passwd').endsWith('.._.._etc_passwd.jsonl')).toBe(true)
  })
})

describe('readMemory', () => {
  it('is empty and not started for a new session', async () => {
    const m = await readMemory('nope')
    expect([m.started, m.roots, m.armed, [...m.alerted]]).toEqual([false, [], [], []])
  })

  it('collects roots, remote MCP servers, alerted keys and the findings that arm data-leaving', async () => {
    await appendLine(line({ event: 'session', roots: ['/home/u/proj'], remote_mcp: { docs: 'mcp.example.com' } }))
    await appendLine(line({ event: 'finding', detector: 'sensitive-access', kind: 'read', severity: 'critical', key: 'k1', alerted: true, label: 'Read ~/.npmrc', tool_use_id: 't1' }))
    await appendLine(line({ event: 'finding', detector: 'sensitive-access', kind: 'read', severity: 'medium', key: 'k2', alerted: false, label: 'Read ~/Documents/a' }))
    await appendLine(line({ event: 'finding', detector: 'sensitive-access', kind: 'write', severity: 'high', key: 'k3', alerted: true, label: 'Write ~/.zshrc' }))
    await appendLine(line({ event: 'finding', detector: 'secret-in-result', severity: 'high', key: 'k4', alerted: false, label: 'a GitHub token from Bash cat x' }))
    const m = await readMemory('s1')
    expect(m.started).toBe(true)
    expect(m.roots).toEqual(['/home/u/proj'])
    expect(m.remoteMcp).toEqual({ docs: 'mcp.example.com' })
    expect([...m.alerted].sort()).toEqual(['k1', 'k3'])
    expect(m.armed.map((a) => a.label)).toEqual(['Read ~/.npmrc', 'a GitHub token from Bash cat x'])
  })

  it('skips a torn last line and lines that are not JSON', async () => {
    await mkdir(auditDir(), { recursive: true })
    await writeFile(sessionFile('s1'), `${JSON.stringify(line({ event: 'session', roots: ['/r'] }))}\nnot json\n{"ts":"2026`)
    expect((await readMemory('s1')).roots).toEqual(['/r'])
  })
})

describe('pruneAudit', () => {
  it('removes audit files older than the retention and keeps newer ones', async () => {
    await appendLine(line({ session_id: 'old' }))
    await appendLine(line({ session_id: 'new' }))
    const old = new Date(Date.now() - 40 * 86_400_000)
    await utimes(sessionFile('old'), old, old)
    expect(await pruneAudit(30)).toBe(1)
    expect(await readMemory('new')).toBeDefined()
    expect(await Bun.file(sessionFile('old')).exists()).toBe(false)
  })

  it('does nothing when there is no audit directory', async () => {
    expect(await pruneAudit(30)).toBe(0)
  })
})

describe('stores', () => {
  it('the in-memory store derives the same memory as the disk store', async () => {
    const { memoryStore, diskStore } = await import('../../src/guard/session')
    const mem = memoryStore()
    const sample = [
      line({ event: 'session', roots: ['/r'], remote_mcp: { d: 'h.example' } }),
      line({ event: 'access', path: '/x' }),
      line({ event: 'finding', detector: 'secret-in-result', severity: 'high', key: 'k', alerted: true, label: 'GitHub token from Read x', tool_use_id: 't9' }),
    ]
    for (const l of sample) {
      await mem.append(l)
      await diskStore.append(l)
    }
    const [a, b] = [await mem.readMemory('s1'), await diskStore.readMemory('s1')]
    expect({ ...a, alerted: [...a.alerted] }).toEqual({ ...b, alerted: [...b.alerted] })
    expect(mem.lines.length).toBe(3)
    expect((await mem.readMemory('other')).started).toBe(false)
  })
})

describe('what arms data-leaving', () => {
  it('a medium secret finding does not arm, a high one does', async () => {
    await appendLine(line({ event: 'finding', detector: 'secret-in-result', severity: 'medium', key: 'w', alerted: false, label: 'password in a URL from Bash psql' }))
    expect((await readMemory('s1')).armed).toEqual([])
    await appendLine(line({ event: 'finding', detector: 'secret-in-result', severity: 'high', key: 'h', alerted: true, label: 'GitHub token from Bash cat x' }))
    expect((await readMemory('s1')).armed.map((a) => a.label)).toEqual(['GitHub token from Bash cat x'])
  })
})

describe('applyLine: pasted secrets', () => {
  it('remembers the fingerprints of secrets pasted in this session', () => {
    const line: AuditLine = { ts: '2026-10-16T10:00:00.000Z', session_id: 's', event: 'finding', detector: 'secret-in-prompt', severity: 'high', fingerprints: ['ab12', 'cd34'], ms: 0 }
    expect([...applyLine(emptyMemory(), line).pasted].sort()).toEqual(['ab12', 'cd34'])
    expect(emptyMemory().pasted.size).toBe(0)
  })
})
