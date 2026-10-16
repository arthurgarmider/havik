import type { Severity } from '../core/types'

// `fetch` is a request whose URL carries no payload: recorded, never a sign of data leaving.
// `use` is a file a program uses without showing its contents, such as the key handed to ssh.
export type AccessKind = 'read' | 'use' | 'write' | 'send' | 'fetch' | 'script' | 'inline-code'
// What one tool call touches. `via` names the tool, and for Bash the program, so messages can say how.
export interface Access { readonly kind: AccessKind; readonly path?: string; readonly host?: string; readonly via: string }

export type Detector = 'sensitive-access' | 'secret-in-result' | 'data-leaving' | 'script-about-to-run'
export interface GuardFinding {
  readonly detector: Detector
  readonly severity: Severity
  readonly key: string
  readonly message: string
  // What a later data-leaving message calls this finding, e.g. "Read ~/.npmrc".
  readonly label: string
  readonly kind?: string
  readonly path?: string
  readonly host?: string
  readonly script?: string
  readonly skill?: string
  readonly evidence: 'observed' | 'static'
  readonly proof?: string
  readonly chain?: readonly string[]
}

// The stdin of a Claude Code hook; only the fields havik reads.
export interface HookEvent {
  readonly session_id: string
  readonly cwd: string
  readonly hook_event_name: string
  readonly permission_mode?: string
  readonly tool_name?: string
  readonly tool_input?: unknown
  readonly tool_response?: unknown
  readonly tool_use_id?: string
  readonly agent_id?: string
  readonly agent_type?: string
  readonly source?: string
  readonly model?: string
}

export type AuditEvent = 'session' | 'access' | 'finding' | 'inline-code' | 'guard-error' | 'budget-exceeded'
export interface AuditLine {
  readonly ts: string
  readonly session_id: string
  readonly event: AuditEvent
  readonly cwd?: string
  readonly permission_mode?: string
  readonly agent_type?: string
  readonly tool_use_id?: string
  readonly tool_name?: string
  readonly detector?: Detector
  readonly severity?: Severity
  readonly key?: string
  readonly kind?: string
  readonly path?: string
  readonly host?: string
  readonly script?: string
  readonly skill?: string
  readonly reason?: string
  readonly label?: string
  readonly snippet?: string
  readonly evidence?: 'observed' | 'static'
  readonly proof?: string
  readonly chain?: readonly string[]
  readonly roots?: readonly string[]
  readonly remote_mcp?: Readonly<Record<string, string>>
  readonly source?: string
  readonly model?: string
  readonly alerted?: boolean
  readonly ms: number
}

// A finding that makes a later send suspicious: a sensitive read or a secret in a result.
export interface Armed { readonly ts: string; readonly label: string; readonly severity: Severity; readonly tool_use_id?: string }
export interface Memory {
  readonly started: boolean
  readonly roots: readonly string[]
  readonly remoteMcp: Readonly<Record<string, string>>
  readonly armed: readonly Armed[]
  readonly alerted: ReadonlySet<string>
}
