import { describe, it, expect } from 'bun:test'
import { join } from 'node:path'
import { chmod, mkdir, writeFile } from 'node:fs/promises'
import { runCli } from '../helpers/scan-cli'
import { withTree } from '../helpers/tmp-tree'

describe('a record file that cannot be read', () => {
  // Root reads any file, and Windows has no such permission.
  it.skipIf(process.getuid?.() === 0 || process.platform === 'win32')('is named on the main screen next to what was read', async () => {
    await withTree({}, async (dir) => {
      const home = join(dir, 'home')
      const cwd = join(home, 'proj')
      await mkdir(join(home, '.claude/projects/p'), { recursive: true })
      await mkdir(join(dir, 'tmp'), { recursive: true })
      const line = { sessionId: 'ok', cwd, timestamp: new Date().toISOString(), type: 'assistant', message: { content: [{ type: 'tool_use', id: 't1', name: 'Read', input: { file_path: join(cwd, 'a.txt') } }] } }
      await writeFile(join(home, '.claude/projects/p/ok.jsonl'), JSON.stringify(line))
      await writeFile(join(home, '.claude/projects/p/locked.jsonl'), JSON.stringify({ ...line, sessionId: 'locked' }))
      await chmod(join(home, '.claude/projects/p/locked.jsonl'), 0o000)
      const r = await runCli([], { HOME: home, HAVIK_HOME: join(dir, 'havik'), TMPDIR: join(dir, 'tmp') }, dir)
      await chmod(join(home, '.claude/projects/p/locked.jsonl'), 0o600)
      expect(r.stderr).toBe('')
      expect(r.stdout).toContain('1 conversations · 1 actions')
      expect(r.stdout).toContain('Could not read: Claude Code: could not read ~/.claude/projects/p/locked.jsonl')
    })
  })

  it.skipIf(process.getuid?.() === 0 || process.platform === 'win32')('makes guard replay exit 3 when nothing worse was found, instead of 0', async () => {
    await withTree({}, async (dir) => {
      const home = join(dir, 'home')
      const file = join(home, '.claude/projects/p/locked.jsonl')
      await mkdir(join(home, '.claude/projects/p'), { recursive: true })
      await mkdir(join(dir, 'tmp'), { recursive: true })
      await writeFile(file, '{}')
      await chmod(file, 0o000)
      const r = await runCli(['guard', 'replay'], { HOME: home, HAVIK_HOME: join(dir, 'havik'), TMPDIR: join(dir, 'tmp') }, dir)
      await chmod(file, 0o600)
      expect(r.stdout).toContain('Could not read: Claude Code: could not read ~/.claude/projects/p/locked.jsonl')
      expect(r.code).toBe(3)
    })
  })
})
