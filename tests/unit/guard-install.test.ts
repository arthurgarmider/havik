import { describe, it, expect } from 'bun:test'
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { TARGETS, TOOL_MATCHER, binaryHookCommand, compareVersions, guardStatus, hasGuard, hookCommand, installGuard, uninstallGuard, withGuard, withGuardFor, withoutGuard } from '../../src/guard/install'
import { withTree } from '../helpers/tmp-tree'

const CMD = hookCommand('/usr/local/bin/node', '/opt/havik/dist/guard.js')
const FOREIGN = { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }

describe('withGuard / withoutGuard', () => {
  it('adds PreToolUse, PostToolUse, SessionStart, UserPromptSubmit and Stop entries and keeps every other hook', () => {
    const next = withGuard({ model: 'x', hooks: { PreToolUse: [FOREIGN], Stop: [FOREIGN] } }, CMD)
    expect(next.model).toBe('x')
    expect(next.hooks.PreToolUse).toEqual([FOREIGN, { matcher: TOOL_MATCHER, hooks: [{ type: 'command', command: CMD, timeout: 5 }] }])
    expect(next.hooks.PostToolUse[0].matcher).toBe(TOOL_MATCHER)
    expect(next.hooks.SessionStart).toEqual([{ hooks: [{ type: 'command', command: CMD, timeout: 5 }] }])
    expect(next.hooks.UserPromptSubmit).toEqual([{ hooks: [{ type: 'command', command: CMD, timeout: 5 }] }])
    expect(next.hooks.Stop).toEqual([FOREIGN, { hooks: [{ type: 'command', command: CMD, timeout: 5 }] }])
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

describe('withGuard over an install from 0.4.0', () => {
  it('replaces the hooks that ran ~/.havik/guard.js with the ones that run guard.mjs', () => {
    const old = withGuard({}, hookCommand('/n', '/home/u/.havik/guard.js'))
    const next = withGuard(old, hookCommand('/n', '/home/u/.havik/guard.mjs'))
    const commands = JSON.stringify(next)
    expect(commands).toContain('guard.mjs')
    expect(commands).not.toContain('guard.js"')
    expect(withoutGuard(old)).toEqual({})
  })
})

describe('hook targets for other agents', () => {
  const cmd = hookCommand('/n', '/home/u/.havik/guard.mjs', 'codex')
  it('names the agent in the command', () => {
    expect(cmd).toBe('"/n" "/home/u/.havik/guard.mjs" --agent codex')
    expect(hookCommand('/n', '/g.mjs')).toBe('"/n" "/g.mjs"')
  })

  it('writes Codex\'s hooks in its Claude-like layout, every tool, timeouts in seconds', () => {
    const next = withGuardFor(TARGETS['codex'], { hooks: { Stop: [FOREIGN] } }, cmd)
    expect(Object.keys(next.hooks).sort()).toEqual(['PostToolUse', 'PreToolUse', 'SessionStart', 'Stop', 'UserPromptSubmit'])
    expect(next.hooks.PreToolUse).toEqual([{ hooks: [{ type: 'command', command: cmd, timeout: 5 }] }])
    expect(next.hooks.Stop[0]).toEqual(FOREIGN)
    expect(withoutGuard(next)).toEqual({ hooks: { Stop: [FOREIGN] } })
  })

  it('writes Gemini CLI\'s own event names, timeouts in milliseconds', () => {
    const next = withGuardFor(TARGETS['gemini-cli'], { theme: 'x' }, cmd)
    expect(Object.keys(next.hooks).sort()).toEqual(['AfterAgent', 'AfterTool', 'BeforeAgent', 'BeforeTool', 'SessionStart'])
    expect(next.hooks.BeforeTool).toEqual([{ matcher: '.*', hooks: [{ type: 'command', command: cmd, timeout: 5000 }] }])
    expect(next.theme).toBe('x')
  })

  it('installs into and removes from the agent\'s own settings file, leaving the rest of the folder alone', async () => {
    await withTree({ '.codex/config.toml': 'approval_policy = "never"\n' }, async (home) => {
      const file = TARGETS['codex'].file(home)
      expect(file).toBe(join(home, '.codex/hooks.json'))
      expect((await installGuard(file, cmd, new Date(), TARGETS['codex'])).ok).toBe(true)
      expect(JSON.parse(await readFile(file, 'utf8')).hooks.UserPromptSubmit[0].hooks[0].command).toBe(cmd)
      expect(await readFile(join(home, '.codex/config.toml'), 'utf8')).toBe('approval_policy = "never"\n')
      expect((await uninstallGuard(file)).ok).toBe(true)
      expect(JSON.parse(await readFile(file, 'utf8'))).toEqual({})
    })
  })
})

describe('Cursor hooks: records only', () => {
  it('writes only after-hooks, in Cursor\'s flat layout with a version, and removes only havik\'s', () => {
    const cmd = hookCommand('/n', '/home/u/.havik/guard.mjs', 'cursor')
    const theirs = { command: './hooks/mine.sh' }
    const next = withGuardFor(TARGETS['cursor'], { version: 1, hooks: { afterFileEdit: [theirs] } }, cmd)
    expect(next.version).toBe(1)
    expect(Object.keys(next.hooks).sort()).toEqual(['afterAgentResponse', 'afterFileEdit', 'afterMCPExecution', 'afterShellExecution'])
    expect(next.hooks.afterFileEdit).toEqual([theirs, { command: cmd, timeout: 5 }])
    expect(Object.keys(next.hooks).some((e) => e.startsWith('before'))).toBe(false)
    expect(withoutGuard(next)).toEqual({ version: 1, hooks: { afterFileEdit: [theirs] } })
    expect(withGuardFor(TARGETS['cursor'], {}, cmd).version).toBe(1)
  })
})

describe('hooks from the standalone program', () => {
  it('run the copy of the program in ~/.havik/bin through its hook command, and are recognised as havik\'s', () => {
    const cmd = binaryHookCommand('/home/u/.havik/bin/havik', 'codex')
    expect(cmd).toBe('"/home/u/.havik/bin/havik" hook --agent codex')
    expect(binaryHookCommand('/home/u/.havik/bin/havik')).toBe('"/home/u/.havik/bin/havik" hook')
    expect(withoutGuard(withGuard({}, binaryHookCommand('/home/u/.havik/bin/havik')))).toEqual({})
  })
})

describe('install: Cursor status and Windows paths', () => {
  it('sees havik in Cursor\'s flat hooks file after an install', async () => {
    await withTree({}, async (home) => {
      const file = TARGETS['cursor'].file(home)
      expect((await installGuard(file, hookCommand('/n', '/home/u/.havik/guard.mjs', 'cursor'), new Date(), TARGETS['cursor'])).ok).toBe(true)
      expect(await hasGuard(file)).toBe(true)
    })
  })

  it('recognises its own hooks with Windows paths, so a re-install replaces them and uninstall removes them', () => {
    for (const cmd of ['"C:\\Users\\u\\.havik\\bin\\havik.exe" hook --agent codex', '"C:\\Program Files\\nodejs\\node.exe" "C:\\Users\\u\\.havik\\guard.mjs"']) {
      expect(withoutGuard(withGuard({}, cmd))).toEqual({})
    }
  })
})
