import { join } from 'node:path'
import { parseMcpServers } from '../adapters/mcp'
import { hostOf, isLocalHost } from '../core/exfil-patterns'
import { readTextHead } from '../core/fs'
import { asRecord } from '../core/json'
import type { SensitivityMap } from '../core/sensitivity'
import { accesses, tildify } from './accesses'
import { atLeast, dataLeaving, isTestRun, mcpServerSends, secretsInResult, sensitiveAccesses, type DetectContext } from './detectors'
import { accessLine, baseLine, clean, findingLine, systemMessage } from './format'
import { scanScript } from './jit'
import { authorizedRoots, judgePath, type GuardConfig } from './policy'
import { pruneAudit, type Store } from './session'
import type { Access, AuditLine, GuardFinding, HookEvent, Memory } from './types'

const PRE_BUDGET_MS = 250
const SCRIPT_BUDGET_MS = 2_000
const POST_BUDGET_MS = 500
// Tools whose result brings new content into the context; an Edit's echo of a file the model already read does not.
const CONTENT_TOOLS = new Set(['Read', 'Bash', 'Grep', 'WebFetch', 'WebSearch', 'Agent', 'Task'])

// Everything one evaluation needs. The hook passes the real clock and the disk store; a replay passes transcript time and memory.
export interface EngineOptions {
  readonly home: string
  readonly config: GuardConfig
  readonly map: SensitivityMap
  readonly store: Store
  readonly now: () => number
  readonly ms: () => number
  readonly spent: () => number
  readonly scanScripts: boolean
  readonly prune: boolean
}

// MCP servers reached over the network, from the project's .mcp.json and ~/.claude.json; learned once per session.
const remoteMcpServers = async (cwd: string, home: string): Promise<Record<string, string>> => {
  const out: Record<string, string> = {}
  const learn = async (path: string, pick: (config: Record<string, any>) => unknown[]) => {
    const head = await readTextHead(path, 5_000_000).catch(() => null)
    if (!head || head.truncated) return
    try {
      const config = asRecord(JSON.parse(head.text))
      for (const entries of pick(config)) {
        for (const s of parseMcpServers(path, head.text, entries)) {
          const host = s.url ? hostOf(s.url) : undefined
          if (host && !isLocalHost(host)) out[s.name] = host
        }
      }
    } catch {
      // an unreadable config teaches nothing
    }
  }
  await learn(join(cwd, '.mcp.json'), c => [c['mcpServers']])
  await learn(join(home, '.claude.json'), c => [c['mcpServers'], asRecord(asRecord(c['projects'])[cwd])['mcpServers']])
  return out
}

const write = (o: EngineOptions, line: AuditLine): Promise<void> => o.store.append(line).catch(() => undefined)

export const startSession = async (event: HookEvent, o: EngineOptions): Promise<void> => {
  await write(o, { ...baseLine(event, o.ms(), o.now()), event: 'session', roots: [event.cwd], remote_mcp: await remoteMcpServers(event.cwd, o.home), source: event.source, model: event.model })
  if (o.prune) await pruneAudit(o.config.retentionDays).catch(() => 0)
}

// Writes every finding and access, and returns the warning for findings that are new and serious enough.
const record = async (event: HookEvent, findings: readonly GuardFinding[], seen: readonly Access[], memory: Memory, o: EngineOptions): Promise<string> => {
  const alerted = new Set(memory.alerted)
  const alerts: GuardFinding[] = []
  for (const f of findings) {
    const alert = atLeast(f.severity, o.config.alertLevel) && !alerted.has(f.key)
    if (alert) {
      alerted.add(f.key)
      alerts.push(f)
    }
    await write(o, findingLine(event, f, alert, o.ms(), o.now()))
  }
  const reported = new Set(findings.flatMap(f => [f.path, f.host, f.script]))
  for (const a of seen) {
    if (a.kind === 'inline-code' || !reported.has(a.path ?? a.host)) await write(o, accessLine(event, a, o.ms(), o.now()))
  }
  return systemMessage(alerts)
}

const contextFor = (event: HookEvent, memory: Memory, o: EngineOptions): DetectContext => ({
  roots: authorizedRoots(event.cwd, memory.roots, o.config, o.home), config: o.config, map: o.map, home: o.home, sessionId: event.session_id, armed: memory.armed, now: o.now(),
})

const withTimeout = <T>(work: Promise<T>, ms: number): Promise<T | null> =>
  Promise.race([work, new Promise<null>(resolve => setTimeout(() => resolve(null), ms).unref())])

const pre = async (event: HookEvent, o: EngineOptions): Promise<string> => {
  let memory = await o.store.readMemory(event.session_id)
  if (!memory.started) {
    await startSession(event, o)
    memory = await o.store.readMemory(event.session_id)
  }
  const ctx = contextFor(event, memory, o)
  const tool = event.tool_name ?? ''
  const list = [...accesses(tool, event.tool_input, event.cwd, o.home), ...mcpServerSends(tool, memory.remoteMcp)]
  const found = sensitiveAccesses(list, ctx)
  const scripts: GuardFinding[] = []
  const toScan = o.scanScripts ? list.filter(a => a.kind === 'script' && a.path) : []
  if (toScan.length > 0 && o.spent() > PRE_BUDGET_MS) {
    await write(o, { ...baseLine(event, o.ms(), o.now()), event: 'budget-exceeded', reason: 'script scan skipped' })
  } else {
    for (const a of toScan) {
      const f = await withTimeout(scanScript(a.path ?? '', o.map, o.home), SCRIPT_BUDGET_MS).catch(() => null)
      if (f) scripts.push(f)
    }
  }
  return record(event, [...found, ...scripts, ...dataLeaving(list, found, ctx)], list, memory, o)
}

const sourceOf = (tool: string, input: unknown, list: readonly Access[], home: string): string => {
  const first = list.find(a => a.kind === 'read' && a.path)
  if (tool === 'Read' && first?.path) return `Read ${tildify(first.path, home)}`
  if (tool === 'Bash') return `Bash ${clean(String(asRecord(input)['command'] ?? ''), 60)}`
  if (tool === 'WebFetch') return `WebFetch ${list.find(a => a.host)?.host ?? ''}`.trim()
  return tool
}

const post = async (event: HookEvent, o: EngineOptions): Promise<string> => {
  const tool = event.tool_name ?? ''
  if (event.tool_response === undefined || !(CONTENT_TOOLS.has(tool) || tool.startsWith('mcp__'))) return ''
  const memory = await o.store.readMemory(event.session_id)
  const ctx = contextFor(event, memory, o)
  const list = accesses(tool, event.tool_input, event.cwd, o.home)
  const critical = list.some(a => a.kind === 'read' && a.path && judgePath(a.path, ctx).level === 'critical')
  const command = tool === 'Bash' ? String(asRecord(event.tool_input)['command'] ?? '') : ''
  const findings = secretsInResult(sourceOf(tool, event.tool_input, list, o.home), event.tool_response, critical, isTestRun(command))
  if (o.spent() > POST_BUDGET_MS) await write(o, { ...baseLine(event, o.ms(), o.now()), event: 'budget-exceeded', reason: 'result check was slow' })
  return record(event, findings, [], memory, o)
}

// One hook event in, at most one warning out. Unknown events are ignored.
export const handleEvent = async (event: HookEvent, o: EngineOptions): Promise<string> => {
  try {
    if (event.hook_event_name === 'SessionStart') {
      await startSession(event, o)
      return ''
    }
    if (event.hook_event_name === 'PreToolUse') return await pre(event, o)
    if (event.hook_event_name === 'PostToolUse') return await post(event, o)
    return ''
  } catch (error) {
    await write(o, { ...baseLine(event, o.ms(), o.now()), event: 'guard-error', reason: clean(String(error), 300) })
    return ''
  }
}
