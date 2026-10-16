import { describe, it, expect } from 'bun:test'
import { mkdir, utimes, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { AGENTS, agentById } from '../../src/agents/registry'
import { expandHome, presenceOf, type Machine } from '../../src/agents/presence'
import type { Proc } from '../../src/agents/processes'
import { mkfifo } from '../helpers/fifo'
import { withTree } from '../helpers/tmp-tree'

const machineAt = (dir: string, processes: Proc[] | string = []): Machine => ({
  home: join(dir, 'home'), platform: 'darwin', appDirs: [join(dir, 'Applications')], pathDirs: [join(dir, 'bin')],
  processes: typeof processes === 'string' ? { ok: false, error: processes } : { ok: true, value: processes },
})
const p = (pid: number, ppid: number, exe: string, extra: Partial<Proc> = {}): Proc => ({ pid, ppid, exe, ...extra })

describe('registry', () => {
  it('names every agent once, in plain words, with home-relative paths', () => {
    expect(new Set(AGENTS.map((a) => a.id)).size).toBe(AGENTS.length)
    expect(AGENTS.length).toBeGreaterThanOrEqual(14)
    for (const a of AGENTS) {
      expect([a.id, a.name.length > 0, typeof a.kind]).toEqual([a.id, true, 'string'])
      for (const path of [...(a.footprint.dirs ?? []), ...(a.footprint.activity ?? []), ...a.paths.data, ...(a.paths.secrets ?? []), ...(a.paths.configs ?? [])]) expect([a.id, path.startsWith('~/')]).toEqual([a.id, true])
    }
    expect(agentById('cursor')?.name).toBe('Cursor')
    // A note goes on its own continuation line under the details: it must fit there whole.
    for (const a of AGENTS) expect([a.id, (a.historyNote ?? '').length <= 56]).toEqual([a.id, true])
  })
})

describe('presenceOf', () => {
  it('finds an agent by its app, its program on the PATH or its data folder', async () => {
    await withTree({ 'Applications/Cursor.app/Contents/Info.plist': '', 'bin/codex': '', 'home/.hermes/config.yaml': 'x' }, async (dir) => {
      const m = machineAt(dir)
      expect((await presenceOf(agentById('cursor')!, m)).installed).toEqual([join(dir, 'Applications/Cursor.app')])
      expect((await presenceOf(agentById('codex')!, m)).installed).toEqual([join(dir, 'bin/codex')])
      expect((await presenceOf(agentById('hermes')!, m)).installed).toEqual(['~/.hermes'])
      expect((await presenceOf(agentById('ollama')!, m)).installed).toEqual([])
    })
  })

  it('says whether it is running, and says nothing when the programs could not be listed', async () => {
    await withTree({}, async (dir) => {
      expect((await presenceOf(agentById('cursor')!, machineAt(dir, [p(10, 1, 'Cursor')]))).running).toBe(true)
      expect((await presenceOf(agentById('hermes')!, machineAt(dir, [p(20, 1, 'python3.12', { script: 'hermes_cli.main' })]))).running).toBe(true)
      expect((await presenceOf(agentById('codex')!, machineAt(dir, [p(10, 1, 'Cursor')]))).running).toBe(false)
      expect((await presenceOf(agentById('codex')!, machineAt(dir, 'not checked'))).running).toBeUndefined()
    })
  })

  it('sees Claude Code installed with npm, which runs as node and its package', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir, [p(40, 1, 'node', { script: 'cli.js', pkg: '@anthropic-ai/claude-code' }), p(41, 40, 'node', { pkg: 'firecrawl-mcp' })])
      const presence = await presenceOf(agentById('claude-code')!, m)
      expect([presence.running, presence.toolServers]).toEqual([true, 1])
    })
  })

  it('tells Claude Code from the Claude desktop app by the program name', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir, [p(30, 1, 'Claude')])
      expect([(await presenceOf(agentById('claude-desktop')!, m)).running, (await presenceOf(agentById('claude-code')!, m)).running]).toEqual([true, false])
    })
  })

  it('counts the tool servers an agent started, through its child processes', async () => {
    await withTree({}, async (dir) => {
      const procs = [p(10, 1, 'Cursor'), p(11, 10, 'node', { pkg: 'firecrawl-mcp' }), p(12, 11, 'node', { pkg: 'left-pad' }), p(13, 11, 'uvx', { script: 'awslabs.aws-mcp-server' }), p(14, 1, 'node', { pkg: 'other-mcp' })]
      expect((await presenceOf(agentById('cursor')!, machineAt(dir, procs))).toolServers).toBe(2)
    })
  })

  it('credits a tool server to the nearest agent above it, so one started by Claude Code inside the desktop app counts once', async () => {
    await withTree({}, async (dir) => {
      const procs = [p(30, 1, 'Claude'), p(31, 30, 'claude'), p(32, 31, 'node', { pkg: 'firecrawl-mcp' }), p(33, 30, 'node', { pkg: 'filesystem-mcp' })]
      const m = machineAt(dir, procs)
      expect([(await presenceOf(agentById('claude-code')!, m)).toolServers, (await presenceOf(agentById('claude-desktop')!, m)).toolServers]).toEqual([1, 1])
    })
  })

  it('dates the last use from the newest file in the agent\'s activity folders', async () => {
    await withTree({ 'home/.codex/sessions/2026/10/01/rollout-a.jsonl': '{}' }, async (dir) => {
      await utimes(join(dir, 'home/.codex/sessions/2026/10/01/rollout-a.jsonl'), new Date('2026-10-01'), new Date('2026-10-01'))
      const presence = await presenceOf(agentById('codex')!, machineAt(dir))
      expect(new Date(presence.lastUsed ?? 0).toISOString().slice(0, 10)).toBe('2026-10-01')
    })
  })

  it('never opens a password or key file of any agent', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir)
      for (const a of AGENTS) {
        for (const path of a.paths.secrets ?? []) {
          await mkdir(dirname(expandHome(path, m.home)), { recursive: true })
          await mkfifo(expandHome(path, m.home)).catch(() => undefined)
        }
      }
      const all = Promise.all(AGENTS.map((a) => presenceOf(a, m)))
      const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('a secrets path was opened')), 2_000))
      expect((await Promise.race([all, timeout]) as unknown[]).length).toBe(AGENTS.length)
    })
  })
})
