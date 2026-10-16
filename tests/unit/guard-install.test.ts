import { describe, it, expect } from 'bun:test'
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { TOOL_MATCHER, compareVersions, guardStatus, hookCommand, installGuard, uninstallGuard, withGuard, withoutGuard } from '../../src/guard/install'
import { withTree } from '../helpers/tmp-tree'

const CMD = hookCommand('/usr/local/bin/node', '/opt/havik/dist/guard.js')
const FOREIGN = { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }

describe('withGuard / withoutGuard', () => {
  it('adds PreToolUse, PostToolUse and SessionStart entries and keeps every other hook', () => {
    const next = withGuard({ model: 'x', hooks: { PreToolUse: [FOREIGN], Stop: [FOREIGN] } }, CMD)
    expect(next.model).toBe('x')
    expect(next.hooks.Stop).toEqual([FOREIGN])
    expect(next.hooks.PreToolUse).toEqual([FOREIGN, { matcher: TOOL_MATCHER, hooks: [{ type: 'command', command: CMD, timeout: 5 }] }])
    expect(next.hooks.PostToolUse[0].matcher).toBe(TOOL_MATCHER)
    expect(next.hooks.SessionStart).toEqual([{ hooks: [{ type: 'command', command: CMD, timeout: 5 }] }])
  })

  it('is idempotent: installing twice leaves one set of havik entries', () => {
    const twice = withGuard(withGuard({}, CMD), hookCommand('/n', '/new/dist/guard.js'))
    expect(twice.hooks.PreToolUse.length).toBe(1)
    expect(twice.hooks.PreToolUse[0].hooks[0].command).toContain('/new/dist/guard.js')
  })

  it('removes exactly what it added, and the hooks key when nothing else is left', () => {
    expect(withoutGuard(withGuard({ theme: 'dark' }, CMD))).toEqual({ theme: 'dark' })
    expect(withoutGuard(withGuard({ hooks: { PreToolUse: [FOREIGN] } }, CMD))).toEqual({ hooks: { PreToolUse: [FOREIGN] } })
  })
})

describe('installGuard / uninstallGuard', () => {
  it('writes a backup before changing an existing file', async () => {
    await withTree({ 'settings.json': JSON.stringify({ theme: 'dark' }) }, async (dir) => {
      const file = join(dir, 'settings.json')
      const r = await installGuard(file, CMD, new Date('2026-10-15T10:00:00Z'))
      expect(r.ok && r.value.backup).toBe(`${file}.bak-2026-10-15T10-00-00-000Z`)
      expect(JSON.parse(await readFile(`${file}.bak-2026-10-15T10-00-00-000Z`, 'utf8'))).toEqual({ theme: 'dark' })
      expect(JSON.parse(await readFile(file, 'utf8')).hooks.SessionStart.length).toBe(1)
      const u = await uninstallGuard(file, new Date('2026-10-15T11:00:00Z'))
      expect(u.ok && u.value.removed).toBe(true)
      expect(JSON.parse(await readFile(file, 'utf8'))).toEqual({ theme: 'dark' })
    })
  })

  it('creates the file and its directory when there is none, without a backup', async () => {
    await withTree({}, async (dir) => {
      const file = join(dir, '.claude/settings.json')
      const r = await installGuard(file, CMD)
      expect(r.ok && r.value.backup).toBeUndefined()
      expect((await readdir(join(dir, '.claude'))).sort()).toEqual(['settings.json'])
    })
  })

  it('refuses a file that is not a JSON object, or hooks in a shape it does not know, and leaves it alone', async () => {
    for (const body of ['{ not json', '[1, 2]', JSON.stringify({ hooks: { PreToolUse: 'oops' } })]) {
      await withTree({ 'settings.json': body }, async (dir) => {
        const r = await installGuard(join(dir, 'settings.json'), CMD)
        expect(r.ok).toBe(false)
        expect(await readFile(join(dir, 'settings.json'), 'utf8')).toBe(body)
        expect(await readdir(dir)).toEqual(['settings.json'])
      })
    }
  })

  it('uninstalling where nothing is installed changes nothing', async () => {
    await withTree({ 'settings.json': '{"theme":"dark"}' }, async (dir) => {
      const u = await uninstallGuard(join(dir, 'settings.json'))
      expect(u.ok && u.value.removed).toBe(false)
      expect(await readdir(dir)).toEqual(['settings.json'])
    })
  })
})

describe('guardStatus', () => {
  it('reports where the guard is installed, stale scripts, the sandbox and disableAllHooks above the working directory', async () => {
    await withTree({}, async (dir) => {
      const home = join(dir, 'home')
      const repo = join(dir, 'repo', 'sub')
      await mkdir(join(home, '.claude'), { recursive: true })
      await mkdir(join(dir, 'repo', '.claude'), { recursive: true })
      await mkdir(repo, { recursive: true })
      await writeFile(join(home, '.claude/settings.json'), JSON.stringify({ ...withGuard({}, hookCommand('/n', join(dir, 'gone/dist/guard.js'))), sandbox: { enabled: true } }))
      await writeFile(join(dir, 'repo/.claude/settings.json'), JSON.stringify({ disableAllHooks: true }))
      const s = await guardStatus(repo, home, '2.1.250')
      expect(s.installedIn).toEqual([join(home, '.claude/settings.json')])
      expect(s.missingScripts).toEqual([join(dir, 'gone/dist/guard.js')])
      expect(s.disabledBy).toEqual([join(dir, 'repo/.claude/settings.json')])
      expect([s.sandbox, s.claudeVersion, s.versionOk]).toEqual([true, '2.1.250', false])
    })
  })

  it('compares versions numerically', () => {
    expect([compareVersions('2.1.251', '2.1.251'), compareVersions('2.1.300', '2.1.251'), compareVersions('2.0.999', '2.1.0')]).toEqual([0, 1, -1])
  })
})
