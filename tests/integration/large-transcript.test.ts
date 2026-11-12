import { describe, it, expect } from 'bun:test'
import { join } from 'node:path'
import { mkdir, writeFile } from 'node:fs/promises'
import { runCli } from '../helpers/scan-cli'
import { withTree } from '../helpers/tmp-tree'

// Node limits how many arguments one call can take; Bun does not, so this only fails with HAVIK_CLI="node dist/havik.js".
const CALLS = 60_000

describe('one very large Claude Code transcript', () => {
  it('is read to the end: 120,000 tool-call events print the screen and exit 0', async () => {
    await withTree({}, async (dir) => {
      const home = join(dir, 'home')
      const cwd = join(home, 'proj')
      await mkdir(join(home, '.claude/projects/p'), { recursive: true })
      await mkdir(join(dir, 'tmp'), { recursive: true })
      const base = { sessionId: 'big', cwd, timestamp: new Date().toISOString() }
      const lines = Array.from({ length: CALLS }, (_, i) => [
        JSON.stringify({ ...base, type: 'assistant', message: { content: [{ type: 'tool_use', id: `t${i}`, name: 'Read', input: { file_path: join(cwd, 'a.txt') } }] } }),
        JSON.stringify({ ...base, type: 'user', toolUseResult: 'ok', message: { content: [{ type: 'tool_result', tool_use_id: `t${i}`, content: 'ok' }] } }),
      ].join('\n'))
      await writeFile(join(home, '.claude/projects/p/big.jsonl'), lines.join('\n'))
      const r = await runCli([], { HOME: home, HAVIK_HOME: join(dir, 'havik'), TMPDIR: join(dir, 'tmp') }, dir)
      expect(r.stderr).toBe('')
      expect(r.code).toBe(0)
      expect(r.stdout).toContain('In the last 30d, from their own records: 1 conversations · 60,000 actions · 1 active days')
    })
  }, 30_000)
})
