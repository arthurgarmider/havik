import { describe, it, expect } from 'bun:test'
import { mkdir, utimes, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { buildOverview } from '../../src/overview'
import { formatAgents } from '../../src/output/overview'
import { AGENTS, agentById } from '../../src/agents/registry'
import { expandHome, type Machine } from '../../src/agents/presence'
import type { Proc } from '../../src/agents/processes'
import type { AgentDef } from '../../src/agents/types'
import { withTree } from '../helpers/tmp-tree'

const DAY = 86_400_000
const NOW = Date.parse('2026-10-16T12:00:00Z')
const machineAt = (dir: string, processes: Proc[] | string = []): Machine => ({
  home: join(dir, 'home'), platform: 'darwin', appDirs: [], pathDirs: [join(dir, 'bin')],
  processes: typeof processes === 'string' ? { ok: false, error: processes } : { ok: true, value: processes },
})

// Puts an agent on the fake machine: its first data folder, and an activity file dated `at`.
const plant = async (m: Machine, def: AgentDef, at?: number): Promise<void> => {
  const dir = def.footprint.dirs?.[0]
  if (dir) await mkdir(expandHome(dir, m.home), { recursive: true })
  else await writeFile(join(m.pathDirs[0], def.footprint.bins?.[0] ?? def.id), '').catch(async () => { await mkdir(m.pathDirs[0], { recursive: true }); await writeFile(join(m.pathDirs[0], def.footprint.bins?.[0] ?? def.id), '') })
  const activity = def.footprint.activity?.[0]
  if (at !== undefined && activity) {
    const file = join(expandHome(activity, m.home), 'x.jsonl')
    await mkdir(dirname(file), { recursive: true })
    await writeFile(file, '{}')
    await utimes(file, new Date(at), new Date(at))
  }
}
// An agent's row and its continuation lines (indented under the details), read as one line.
const lineOf = (text: string, name: string): string => {
  const lines = text.split('\n')
  const start = lines.findIndex((l) => l.trimStart().startsWith(name))
  if (start < 0) return ''
  const rest = lines.slice(start + 1)
  const end = rest.findIndex((l) => !/^ {10,}\S/.test(l))
  return [lines[start], ...rest.slice(0, end < 0 ? rest.length : end).map((l) => l.trim())].join(' · ')
}
const withAgent = (id: string, over: Partial<AgentDef>): AgentDef => ({ ...agentById(id)!, ...over })

describe('formatAgents', () => {
  it('puts running agents first, then the most recently used, and the unused ones on one line', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir, [{ pid: 1, ppid: 0, exe: 'Cursor' }])
      const agents = ['codex', 'cursor', 'hermes', 'opencode'].map((id) => agentById(id)!)
      await plant(m, agentById('codex')!, NOW - 21 * DAY)
      await plant(m, agentById('cursor')!)
      await plant(m, agentById('hermes')!, NOW - DAY)
      await plant(m, agentById('opencode')!)
      const text = formatAgents(await buildOverview(m, { agents, now: NOW }), NOW)
      const order = ['Cursor', 'Hermes Agent', 'Codex'].map((n) => text.indexOf(`  ${n} `))
      expect(order.every((i, k) => i > 0 && (k === 0 || i > order[k - 1]))).toBe(true)
      expect(lineOf(text, 'Cursor')).toContain('running now')
      expect(lineOf(text, 'Codex')).toContain('used 21 days ago')
      expect(lineOf(text, 'Hermes Agent')).toContain('used yesterday')
      expect(lineOf(text, 'Not used yet:')).toContain('opencode')
    })
  })

  it('says what an agent is connected to, in plain words', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir)
      const hermes = withAgent('hermes', { setup: async () => ({ toolServers: [], channels: ['Telegram'], schedules: 3, approvals: 'asks first', warnings: [] }) })
      const cursor = withAgent('cursor', { setup: async () => ({ toolServers: [{ name: 'a', configPath: 'x', transport: 'stdio', secrets: [{ kind: 'env', key: 'TOKEN' }] }, { name: 'b', configPath: 'x', transport: 'stdio' }], channels: [], schedules: 0, warnings: [] }) })
      await plant(m, hermes, NOW)
      await plant(m, cursor, NOW)
      const text = formatAgents(await buildOverview(m, { agents: [hermes, cursor], now: NOW }), NOW)
      expect(lineOf(text, 'Hermes Agent')).toContain('starts itself on 3 schedules · reachable from Telegram · asks first')
      expect(lineOf(text, 'Cursor')).toContain('2 tool servers (1 keeps a password in its settings file)')
      expect(text).not.toMatch(/\bMCP\b|session|tool call/i)
    })
  })

  it('gives an agent that was never used its own row when it is set up to act without asking', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir)
      const codex = withAgent('codex', { setup: async () => ({ toolServers: [], channels: [], schedules: 0, approvals: 'runs without asking', warnings: [] }) })
      await plant(m, codex)
      await plant(m, agentById('opencode')!)
      const text = formatAgents(await buildOverview(m, { agents: [codex, agentById('opencode')!], now: NOW }), NOW)
      expect(lineOf(text, 'Codex')).toContain('installed')
      expect(lineOf(text, 'Codex')).toContain('runs without asking')
      expect(lineOf(text, 'Not used yet:')).toBe('  Not used yet: opencode')
    })
  })

  it('says how much each agent did in the window, and how much of it havik understood', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir, [{ pid: 1, ppid: 0, exe: 'Cursor' }, { pid: 2, ppid: 0, exe: 'claude' }])
      await plant(m, agentById('cursor')!)
      await plant(m, agentById('claude-code')!)
      const o = await buildOverview(m, { agents: [agentById('cursor')!, agentById('claude-code')!], now: NOW })
      const text = formatAgents(o, NOW, { cursor: { sessions: 61, toolCalls: 9120, unknownActions: 282 }, 'claude-code': { sessions: 25, toolCalls: 54318, unknownActions: 0 } })
      expect(lineOf(text, 'Cursor')).toContain('61 conversations · 9,120 actions (97% understood)')
      expect(lineOf(text, 'Claude Code')).toContain('25 conversations · 54,318 actions')
      expect(lineOf(text, 'Claude Code')).not.toContain('understood')
      const quiet = formatAgents(o, NOW, { cursor: { sessions: 65, toolCalls: 0, unknownActions: 0 } })
      expect(lineOf(quiet, 'Cursor')).toContain('65 conversations, no actions')
    })
  })

  it('in the compact form, gives each agent at most two lines, the most telling facts first', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir, 'not checked')
      for (const [i, a] of AGENTS.entries()) await plant(m, a, NOW - i * DAY)
      const hermes = withAgent('hermes', { setup: async () => ({ toolServers: [], channels: ['Telegram'], schedules: 3, approvals: 'asks first', warnings: [] }) })
      const agents = AGENTS.map((a) => (a.id === 'hermes' ? hermes : a))
      const text = formatAgents(await buildOverview(m, { agents, now: NOW }), NOW, { 'claude-code': { sessions: 1552, toolCalls: 54798, unknownActions: 28 } }, { compact: true })
      const lines = text.split('\n')
      expect(lines.length).toBeLessThanOrEqual(16)
      expect(lines.filter((l) => [...l].length > 100)).toEqual([])
      // At most one continuation line per agent.
      expect(lines.some((l, i) => i > 0 && /^ {10,}\S/.test(l) && /^ {10,}\S/.test(lines[i - 1]))).toBe(false)
      expect(lineOf(text, 'Claude Code')).toContain('1,552 conversations · 54,798 actions')
      expect(lineOf(text, 'Hermes Agent')).toMatch(/self-running agent · starts itself on 3 schedules · reachable from Telegram/)
    })
  })

  it('names why there is no history for agents havik only finds', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir)
      await plant(m, agentById('chatgpt-atlas')!, NOW - 61 * DAY)
      expect(formatAgents(await buildOverview(m, { agents: [agentById('chatgpt-atlas')!], now: NOW }), NOW)).toContain('its history is encrypted, havik cannot see it')
    })
  })

  it('fits one screen with every agent havik knows, and says when it could not see running programs', async () => {
    await withTree({}, async (dir) => {
      const m = machineAt(dir, 'not checked')
      for (const [i, a] of AGENTS.entries()) await plant(m, a, NOW - i * DAY)
      const text = formatAgents(await buildOverview(m, { now: NOW }), NOW)
      expect(text.split('\n').length).toBeLessThanOrEqual(24)
      expect(text.split('\n').filter((l) => l.length > 100)).toEqual([])
      expect(text).toContain('havik could not see which programs are running')
    })
  })

  it('says so plainly when no agent is found', async () => {
    await withTree({}, async (dir) => expect(formatAgents(await buildOverview(machineAt(dir), { now: NOW }), NOW)).toContain('No AI agents found on this computer.'))
  })
})
