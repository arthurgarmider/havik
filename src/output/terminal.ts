import chalk from 'chalk'
import type { Finding, ScanResult, Severity } from '../core/types'
import { trace } from '../core/trace'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low']

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.red,
  high: chalk.yellow,
  medium: chalk.blue,
  low: chalk.gray,
}

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '🔴',
  high: '🟡',
  medium: '🔵',
  low: '⚪',
}

const REDACTED_MSG = '[REDACTED — contains potential credentials]'

function buildScoreBar(percentage: number): string {
  const filled = Math.round((percentage / 100) * 20)
  return '█'.repeat(filled) + '░'.repeat(20 - filled)
}

function formatProof(finding: Finding): string {
  if (!finding.proof) return ''
  const { file, line, snippet, safeToDisplay } = finding.proof
  const display = safeToDisplay ? `\n       │ ${snippet}` : `\n       │ ${REDACTED_MSG}`
  return `\n     Proof: ${file}:${line}${display}`
}

function formatFinding(finding: Finding): string {
  const icon = SEVERITY_ICON[finding.severity]
  const proof = formatProof(finding)
  const rule = `\n     Rule: ${finding.ruleId} (${finding.owasp})`
  return `  ${icon} ${finding.id}: ${finding.description}${proof}${rule}`
}

function formatSeverityGroup(severity: Severity, findings: Finding[], verbose: boolean): string {
  const color = SEVERITY_COLOR[severity]
  const header = color(`  ${severity.toUpperCase()}  severity:${severity}  confidence:${findings[0].confidence}`)
  const divider = color('  ' + '─'.repeat(44))

  if (verbose || severity === 'critical') {
    const body = findings.map(formatFinding).join('\n')
    return `${header}\n${divider}\n${body}`
  }

  const icon = SEVERITY_ICON[severity]
  const summary = `  ${icon} ${findings.length} skill${findings.length > 1 ? 's' : ''} with undeclared ${severity} findings`
  return `${header}\n${divider}\n${summary}`
}

function formatHeader(result: ScanResult): string {
  const { agents, skills, mcpServers } = result.inventory
  const agentCount = agents.length
  const skillCount = skills.length
  const mcpCount = mcpServers.length
  return [
    '',
    '  Scanning agent environment...',
    '',
    `  Found: ${agentCount} agent · ${skillCount} skills · ${mcpCount} MCP servers`,
    '',
  ].join('\n')
}

function formatScore(result: ScanResult): string {
  const { grade, percentage } = result.score
  const bar = buildScoreBar(percentage)
  return [
    '',
    `  Agent Security Score: ${grade}`,
    '  ' + '━'.repeat(23),
    `  ${bar} ${percentage}%`,
    '',
  ].join('\n')
}

export const formatTerminal = trace(
  'formatTerminal',
  (result: ScanResult, verbose: boolean): string => {
    const header = formatHeader(result)

    const grouped = SEVERITY_ORDER.reduce<Record<Severity, Finding[]>>(
      (acc, sev) => ({ ...acc, [sev]: result.findings.filter(f => f.severity === sev) }),
      { critical: [], high: [], medium: [], low: [] }
    )

    const sections = SEVERITY_ORDER
      .filter(sev => grouped[sev].length > 0)
      .map(sev => formatSeverityGroup(sev, grouped[sev], verbose))
      .join('\n\n')

    const score = formatScore(result)

    return `${header}${sections}${score}`
  }
)
