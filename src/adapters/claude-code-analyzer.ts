import { trace } from '../core/trace'
import { isDangerousExec, touchesSensitivePath } from '../core/shell-patterns'
import { redactSecrets } from '../core/redact'
import type {
  Finding,
  Result,
  ClaudeCodeInventory,
  HookInfo,
  SkillDefInfo,
  PermissionEntry,
  AgentDefInfo,
} from '../core/types'

const EXFIL_PATTERNS = /https?:\/\/(?!localhost|127\.0\.0\.1)/i
const OVERLY_PERMISSIVE_BASH = /^Bash\(\*\)$|^Bash$/
const OVERLY_PERMISSIVE_READ = /^Read\(\/\*\*?\)$|^Read\(\/\)$/
const WILDCARD_DANGEROUS = /^(WebSearch|Write|Edit|MultiEdit)\(\*\)$|^\*$/

let counter = 0
const nextId = () => `CC-${String(++counter).padStart(3, '0')}`

const makeProof = (file: string, snippet: string): Finding['proof'] => ({
  file,
  line: 1,
  snippet: redactSecrets(snippet),
  safeToDisplay: true,
})

const checkHooks = (hooks: readonly HookInfo[], findings: Finding[]): void => {
  for (const hook of hooks) {
    const exec = isDangerousExec(hook.command)
    if (exec || touchesSensitivePath(hook.command)) {
      findings.push({
        id: nextId(),
        ruleId: 'dangerous-hook-command',
        severity: exec ? 'critical' : 'high',
        confidence: 'high',
        owasp: 'ASI02',
        description: `Hook from "${hook.source}" executes dangerous command pattern`,
        proof: makeProof(hook.source, hook.command.slice(0, 120)),
      })
    }

    if (EXFIL_PATTERNS.test(hook.command)) {
      findings.push({
        id: nextId(),
        ruleId: 'hook-data-exfiltration',
        severity: 'critical',
        confidence: 'high',
        owasp: 'ASI04',
        description: `Hook from "${hook.source}" sends data to external endpoint`,
        proof: makeProof(hook.source, hook.command.slice(0, 120)),
      })
    }

    if (hook.matcher === '*') {
      findings.push({
        id: nextId(),
        ruleId: 'wildcard-hook-matcher',
        severity: 'high',
        confidence: 'high',
        owasp: 'ASI02',
        description: `Hook from "${hook.source}" uses wildcard matcher — fires on ALL tool calls`,
        proof: makeProof(hook.source, `matcher: "${hook.matcher}", event: ${hook.event}`),
      })
    }
  }
}

const checkPermissions = (permissions: readonly PermissionEntry[], findings: Finding[]): void => {
  for (const perm of permissions) {
    if (OVERLY_PERMISSIVE_BASH.test(perm.pattern)) {
      findings.push({
        id: nextId(),
        ruleId: 'overly-permissive-bash',
        severity: 'high',
        confidence: 'high',
        owasp: 'ASI03',
        description: 'Bash permission allows unrestricted command execution',
        proof: makeProof(perm.source, perm.pattern),
      })
    }

    if (OVERLY_PERMISSIVE_READ.test(perm.pattern)) {
      findings.push({
        id: nextId(),
        ruleId: 'overly-permissive-read',
        severity: 'high',
        confidence: 'high',
        owasp: 'ASI03',
        description: 'Read permission grants full filesystem read access',
        proof: makeProof(perm.source, perm.pattern),
      })
    }

    if (WILDCARD_DANGEROUS.test(perm.pattern)) {
      findings.push({
        id: nextId(),
        ruleId: 'wildcard-tool-permission',
        severity: 'high',
        confidence: 'high',
        owasp: 'ASI03',
        description: `Wildcard permission on potentially dangerous tool: ${perm.pattern}`,
        proof: makeProof(perm.source, perm.pattern),
      })
    }
  }
}

const checkSkills = (skills: readonly SkillDefInfo[], findings: Finding[]): void => {
  for (const skill of skills) {
    if (skill.allowedTools.includes('Bash')) {
      findings.push({
        id: nextId(),
        ruleId: 'skill-with-bash-access',
        severity: 'medium',
        confidence: 'high',
        owasp: 'ASI02',
        description: `Skill "${skill.name}" has Bash tool access — can execute arbitrary commands`,
        proof: makeProof(skill.path, `allowedTools: [${skill.allowedTools.join(', ')}]`),
      })
    }
  }
}

const checkSettings = (autoApproveProjectMcp: string | undefined, findings: Finding[]): void => {
  if (!autoApproveProjectMcp) return
  findings.push({
    id: nextId(),
    ruleId: 'mcp-enable-all-project-servers',
    severity: 'high',
    confidence: 'high',
    owasp: 'ASI04',
    description: 'Settings auto-approve every MCP server a project declares (enableAllProjectMcpServers)',
    proof: makeProof(autoApproveProjectMcp, 'enableAllProjectMcpServers: true'),
  })
}

const checkHooksDisabled = (path: string | undefined, findings: Finding[]): void => {
  if (!path) return
  findings.push({
    id: nextId(),
    ruleId: 'hooks-disabled-by-project',
    severity: 'high',
    confidence: 'high',
    owasp: 'ASI02',
    description: 'Settings switch off every hook, including user-level guards such as havik guard (disableAllHooks)',
    proof: makeProof(path, 'disableAllHooks: true'),
  })
}

const checkAgents = (agents: readonly AgentDefInfo[], findings: Finding[]): void => {
  for (const agent of agents) {
    if (agent.tools?.includes('Bash')) {
      findings.push({
        id: nextId(),
        ruleId: 'agent-unrestricted-bash',
        severity: 'high',
        confidence: 'high',
        owasp: 'ASI02',
        description: `Agent "${agent.name}" has unrestricted Bash tool access`,
        proof: makeProof(agent.path, `tools: [${agent.tools.join(', ')}]`),
      })
    }
  }
}

export const analyzeClaudeCode = trace(
  'analyzeClaudeCode',
  (inventory: ClaudeCodeInventory): Result<readonly Finding[]> => {
    counter = 0
    const findings: Finding[] = []

    checkHooks(inventory.hooks, findings)
    checkPermissions(inventory.permissions, findings)
    checkSettings(inventory.autoApproveProjectMcp, findings)
    checkHooksDisabled(inventory.hooksDisabledBy, findings)
    checkSkills(inventory.skills, findings)
    checkAgents(inventory.agents, findings)

    return { ok: true, value: findings }
  }
)
