export type Capability = 'network' | 'shell' | 'filesystem.read' | 'filesystem.write' | 'credentials'

export interface CapabilityResult {
  readonly observed: ReadonlySet<Capability>
  readonly declared: ReadonlySet<Capability>
  readonly undeclared: ReadonlySet<Capability>
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Confidence = 'high' | 'medium' | 'low'

export interface Proof {
  readonly file: string
  readonly line: number
  readonly snippet: string
  readonly safeToDisplay: boolean
}

export interface Finding {
  readonly id: string
  readonly ruleId: string
  readonly severity: Severity
  readonly confidence: Confidence
  readonly owasp: string
  readonly description: string
  readonly capabilities?: CapabilityResult
  readonly proof?: Proof
}

export type RuleType = 'capability_mismatch' | 'pattern'

export interface Rule {
  readonly id: string
  readonly type: RuleType
  readonly severity: Severity
  readonly confidence: Confidence
  readonly owasp: string
  readonly frameworks: readonly string[]
  readonly description: string
  readonly match: Record<string, unknown>
  readonly metadata?: RuleMetadata
}

export interface RuleMetadata {
  readonly author: string
  readonly created: string
  readonly references?: readonly string[]
}

export interface SkillInfo {
  readonly name: string
  readonly path: string
  readonly hash: string
  readonly manifest?: Record<string, unknown>
  readonly sourceFiles: readonly string[]
}

export interface AgentInventory {
  readonly framework: string
  readonly agents: readonly AgentInfo[]
  readonly skills: readonly SkillInfo[]
  readonly mcpServers: readonly McpServerInfo[]
  readonly warnings?: readonly string[]
}

export interface AgentInfo {
  readonly name: string
  readonly configPath: string
  readonly bindAddress?: string
  readonly port?: number
}

// A credential-looking value found in a server's env or headers. Only the key is kept, never the value.
export interface McpSecret {
  readonly kind: 'env' | 'header'
  readonly key: string
}

export interface McpServerInfo {
  readonly name: string
  readonly configPath: string
  readonly transport: 'stdio' | 'sse'
  readonly version?: string
  readonly command?: string
  readonly args?: readonly string[]
  readonly url?: string
  readonly envKeys?: readonly string[]
  readonly secrets?: readonly McpSecret[]
  readonly line?: number
}

export interface FrameworkAdapter {
  readonly name: string
  readonly version: string
  detect(): Promise<boolean>
  discover(): Promise<AgentInventory>
  analyze(rules: readonly Rule[]): Promise<readonly Finding[]>
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

export interface PostureScore {
  readonly grade: Grade
  readonly percentage: number
  readonly findingCounts: Record<Severity, number>
  readonly owaspCoverage: Record<string, number>
}

export interface ScanResult {
  readonly timestamp: string
  readonly inventory: AgentInventory
  readonly findings: readonly Finding[]
  readonly score: PostureScore
  // Things havik could not read or had to skip; any warning means the scan is incomplete.
  readonly warnings: readonly string[]
  readonly scanDurationMs: number
}

export type Result<T, E = string> = { ok: true; value: T } | { ok: false; error: E }

// === Claude Code ===

export interface ClaudeCodeInventory {
  readonly plugins: readonly PluginInfo[]
  readonly hooks: readonly HookInfo[]
  readonly agents: readonly AgentDefInfo[]
  readonly skills: readonly SkillDefInfo[]
  readonly permissions: readonly PermissionEntry[]
  readonly mcpServers: readonly McpServerInfo[]
  readonly autoApproveProjectMcp?: string
  readonly hooksDisabledBy?: string
  readonly warnings: readonly string[]
}

export interface PluginInfo {
  readonly name: string
  readonly marketplace: string
  readonly version: string
  readonly installPath: string
  readonly gitSha?: string
  readonly enabled: boolean
  readonly blocked: boolean
}

export interface HookInfo {
  readonly event: string
  readonly matcher: string
  readonly command: string
  readonly source: string
  readonly async: boolean
  readonly timeout: number
}

export interface AgentDefInfo {
  readonly name: string
  readonly path: string
  readonly tools: readonly string[]
  readonly model?: string
}

export interface SkillDefInfo {
  readonly name: string
  readonly path: string
  readonly allowedTools: readonly string[]
  readonly pluginSource?: string
}

export interface PermissionEntry {
  readonly pattern: string
  readonly source: string
}
