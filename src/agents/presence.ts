import { stat } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { newestMtime, pathExists } from '../core/fs'
import type { Result } from '../core/types'
import { tildify } from '../guard/accesses'
import { listProcesses, type Proc } from './processes'
import { AGENTS } from './registry'
import type { AgentDef } from './types'

// The facts about this computer that presence needs; injected so tests never depend on the real machine.
export interface Machine {
  readonly home: string
  readonly platform: string
  readonly appDirs: readonly string[]
  readonly pathDirs: readonly string[]
  readonly processes: Result<readonly Proc[]>
}

export interface Presence {
  readonly installed: readonly string[]  // where it was found
  readonly running?: boolean             // undefined when the running programs could not be listed
  readonly lastUsed?: number
  readonly toolServers: number           // running tool servers it started
}

const EXTRA_BIN_DIRS = ['.local/bin', '.npm-global/bin', '.bun/bin', '.cargo/bin']
const TOOL_SERVER = /mcp/i
const MAX_PARENTS = 30

export const expandHome = (path: string, home: string): string => (path.startsWith('~/') ? join(home, path.slice(2)) : path)

export const machine = async (): Promise<Machine> => {
  const home = homedir()
  const pathDirs = [...(process.env.PATH ?? '').split(':').filter(Boolean), ...EXTRA_BIN_DIRS.map(d => join(home, d)), '/opt/homebrew/bin', '/usr/local/bin']
  return {
    home, platform: process.platform, pathDirs: [...new Set(pathDirs)],
    appDirs: process.platform === 'darwin' ? ['/Applications', join(home, 'Applications')] : [],
    processes: await listProcesses(),
  }
}

const isAgentProcess = (def: AgentDef, p: Proc): boolean =>
  (def.footprint.processes ?? []).some(name => p.exe === name || (p.script?.startsWith(name) ?? false))

const isToolServer = (p: Proc): boolean => [p.exe, p.script, p.pkg].some(s => s !== undefined && TOOL_SERVER.test(s))

// A tool server belongs to the nearest agent among its parents: one Claude Code started inside the desktop app is Claude Code's.
const startedBy = (p: Proc, def: AgentDef, agents: readonly AgentDef[], byPid: ReadonlyMap<number, Proc>): boolean => {
  let parent = byPid.get(p.ppid)
  for (let i = 0; parent && i < MAX_PARENTS; i++) {
    const at = parent
    const owner = agents.find(a => isAgentProcess(a, at))
    if (owner) return owner.id === def.id
    parent = byPid.get(at.ppid)
  }
  return false
}

const lastUsedOf = async (paths: readonly string[]): Promise<number | undefined> => {
  const times = await Promise.all(paths.map(async (path) => {
    const info = await stat(path).catch(() => null)
    if (!info) return undefined
    return info.isDirectory() ? newestMtime(path, { depth: 5 }) : info.mtimeMs
  }))
  const known = times.filter((t): t is number => t !== undefined)
  return known.length > 0 ? Math.max(...known) : undefined
}

export const presenceOf = async (def: AgentDef, m: Machine, agents: readonly AgentDef[] = AGENTS): Promise<Presence> => {
  const f = def.footprint
  const candidates = [
    ...(f.apps ?? []).flatMap(app => m.appDirs.map(dir => join(dir, `${app}.app`))),
    ...(f.bins ?? []).flatMap(bin => m.pathDirs.map(dir => join(dir, bin))),
    ...(f.dirs ?? []).map(dir => expandHome(dir, m.home)),
  ]
  const found = (await Promise.all(candidates.map(async path => ((await pathExists(path)) ? tildify(path, m.home) : undefined))))
  const installed = [...new Set(found.filter((p): p is string => p !== undefined))]
  const lastUsed = await lastUsedOf((f.activity ?? []).map(path => expandHome(path, m.home)))
  if (!m.processes.ok) return { installed, lastUsed, toolServers: 0 }
  const procs = m.processes.value
  const byPid = new Map(procs.map(p => [p.pid, p]))
  const toolServers = procs.filter(p => isToolServer(p) && startedBy(p, def, agents, byPid)).length
  return { installed, running: procs.some(p => isAgentProcess(def, p)), lastUsed, toolServers }
}
