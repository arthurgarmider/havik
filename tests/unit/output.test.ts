import { describe, it, expect } from 'bun:test'
import { formatTerminal } from '../../src/output/terminal'
import { formatJson } from '../../src/output/json'
import type { ScanResult, Finding, CapabilityResult } from '../../src/core/types'

const makeScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
  timestamp: '2026-03-26T00:00:00.000Z',
  scanDurationMs: 100,
  inventory: {
    framework: 'openclaw',
    agents: [{ name: 'agent-1', configPath: '/tmp/agent.json' }],
    skills: Array.from({ length: 14 }, (_, i) => ({
      name: `skill-${i}`,
      path: `/tmp/skill-${i}`,
      hash: `hash${i}`,
      sourceFiles: [],
    })),
    mcpServers: [
      { name: 'mcp-1', configPath: '/tmp/mcp.json', transport: 'stdio' },
      { name: 'mcp-2', configPath: '/tmp/mcp2.json', transport: 'sse' },
      { name: 'mcp-3', configPath: '/tmp/mcp3.json', transport: 'stdio' },
    ],
  },
  findings: [],
  score: {
    grade: 'D',
    percentage: 30,
    findingCounts: { critical: 1, high: 4, medium: 0, low: 0 },
    owaspCoverage: { ASI02: 1 },
  },
  ...overrides,
})

const makeCriticalFinding = (): Finding => ({
  id: 'SK-001',
  ruleId: 'undeclared-capability-mismatch',
  severity: 'critical',
  confidence: 'high',
  owasp: 'ASI02',
  description: 'skill "auto-backup" has undeclared network + credential access',
  proof: {
    file: '~/.openclaw/skills/auto-backup/index.ts',
    line: 34,
    snippet: 'const resp = await fetch(...)',
    safeToDisplay: true,
  },
})

const makeUnsafeFinding = (): Finding => ({
  id: 'SK-002',
  ruleId: 'credential-leak',
  severity: 'critical',
  confidence: 'high',
  owasp: 'ASI03',
  description: 'potential credential exposure',
  proof: {
    file: '~/.openclaw/skills/bad/index.ts',
    line: 10,
    snippet: 'const token = "sk-secret-123"',
    safeToDisplay: false,
  },
})

describe('formatTerminal', () => {
  it('includes CRITICAL header for critical findings', () => {
    const result = makeScanResult({ findings: [makeCriticalFinding()] })
    const output = formatTerminal(result, false)
    expect(output).toContain('CRITICAL')
  })

  it('shows proof with file and line', () => {
    const result = makeScanResult({ findings: [makeCriticalFinding()] })
    const output = formatTerminal(result, true)
    expect(output).toContain('~/.openclaw/skills/auto-backup/index.ts:34')
    expect(output).toContain('const resp = await fetch(...)')
  })

  it('redacts unsafe snippets', () => {
    const result = makeScanResult({ findings: [makeUnsafeFinding()] })
    const output = formatTerminal(result, true)
    expect(output).toContain('[REDACTED — contains potential credentials]')
    expect(output).not.toContain('sk-secret-123')
  })

  it('shows score bar', () => {
    const result = makeScanResult()
    const output = formatTerminal(result, false)
    expect(output).toContain('Agent Security Score: D')
    expect(output).toContain('30%')
    expect(output).toMatch(/[█░]+/)
  })
})

describe('formatJson', () => {
  it('produces valid JSON', () => {
    const result = makeScanResult()
    const json = formatJson(result)
    expect(() => JSON.parse(json)).not.toThrow()
    const parsed = JSON.parse(json)
    expect(parsed.timestamp).toBe('2026-03-26T00:00:00.000Z')
  })

  it('converts Sets to arrays', () => {
    const capabilities: CapabilityResult = {
      observed: new Set(['network', 'credentials']),
      declared: new Set(['network']),
      undeclared: new Set(['credentials']),
    }
    const finding: Finding = {
      id: 'SK-003',
      ruleId: 'cap-mismatch',
      severity: 'high',
      confidence: 'high',
      owasp: 'ASI02',
      description: 'undeclared credentials',
      capabilities,
    }
    const result = makeScanResult({ findings: [finding] })
    const json = formatJson(result)
    const parsed = JSON.parse(json)
    const parsedCaps = parsed.findings[0].capabilities
    expect(Array.isArray(parsedCaps.observed)).toBe(true)
    expect(parsedCaps.observed).toContain('network')
    expect(parsedCaps.undeclared).toContain('credentials')
  })
})
