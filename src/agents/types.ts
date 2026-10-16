import type { McpServerInfo } from '../core/types'
import type { Replayed } from '../guard/types'

// What kind of helper this is, in the words a person uses for it.
export type AgentKind = 'coding assistant' | 'desktop assistant' | 'browser agent' | 'self-running agent' | 'local model' | 'agent runner'

// How havik notices an agent: found with stat alone, never opened. Paths start with ~/.
export interface Footprint {
  readonly apps?: readonly string[]       // app bundle names in /Applications, without .app
  readonly bins?: readonly string[]       // program names on the PATH
  readonly dirs?: readonly string[]       // data folders or files
  readonly activity?: readonly string[]   // where its newest file says when it was last used
  readonly processes?: readonly string[]  // running program names, or the start of a runner's script name
}

export interface AgentPaths {
  readonly data: readonly string[]           // everything the agent keeps
  readonly conversations?: readonly string[] // its records of what it did: private, critical for any other agent
  readonly configs?: readonly string[]       // settings havik reads with values reduced to key names; critical for others
  readonly secrets?: readonly string[]       // its passwords and tokens: havik never opens them
}

// What an agent is connected to and allowed to do, read from its settings.
export interface AgentSetup {
  readonly toolServers: readonly McpServerInfo[]
  readonly channels: readonly string[]    // chat apps that can reach it: Telegram, Slack, …
  readonly schedules: number              // jobs it starts by itself
  readonly approvals?: 'asks first' | 'runs without asking'
  readonly warnings: readonly string[]
}

// One conversation from an agent's own records, as hook events in time order.
export interface AgentSession {
  readonly id: string
  readonly startedBy: 'you' | 'schedule' | 'chat' | 'unknown'
  readonly events: readonly Replayed[]
  readonly unknown?: Readonly<Record<string, number>>  // tool names havik does not understand, and how often
}
// A history reader yields conversations, or a warning when part of its records could not be read.
export type HistoryItem = AgentSession | { readonly warning: string }
export interface HistoryOptions { readonly home: string; readonly since?: number; readonly now: number; readonly dir?: string }

export interface AgentDef {
  readonly id: string
  readonly name: string
  readonly kind: AgentKind
  readonly footprint: Footprint
  readonly paths: AgentPaths
  readonly setup?: (home: string) => Promise<AgentSetup>
  readonly history?: (o: HistoryOptions) => AsyncIterable<HistoryItem>
  readonly historyNote?: string           // why havik cannot show what it did, in plain words
}
