import { join } from 'path'
import { homedir } from 'os'
import * as yaml from 'js-yaml'
import { trace } from './trace'
import { readTextOrNull } from './fs'

export interface SensitivityEntry {
  readonly pattern: string
  readonly reason: string
}

export type SensitivityLevel = 'critical' | 'high' | 'medium' | 'low'

export type SensitivityMap = Record<SensitivityLevel, readonly SensitivityEntry[]>

export const DEFAULTS: SensitivityMap = {
  critical: [
    { pattern: '~/.ssh/', reason: 'SSH private keys' },
    { pattern: 'process.env', reason: 'Environment variables with API keys and tokens' },
    { pattern: '~/.aws/', reason: 'AWS credentials' },
    { pattern: '~/.claude/', reason: 'Claude Code config and session data' },
    { pattern: '~/.gnupg/', reason: 'GPG private keys' },
    { pattern: '~/.kube/', reason: 'Kubernetes credentials' },
    { pattern: '~/.docker/', reason: 'Docker credentials' },
    { pattern: '~/.npmrc', reason: 'npm auth tokens' },
    { pattern: '~/.netrc', reason: 'Stored network logins' },
    { pattern: '~/.pypirc', reason: 'PyPI upload tokens' },
    { pattern: '~/.git-credentials', reason: 'Stored git logins' },
    { pattern: '/etc/shadow', reason: 'System password hashes' },
    { pattern: '~/.azure/', reason: 'Azure credentials' },
    { pattern: '~/.config/gcloud/', reason: 'Google Cloud credentials' },
    { pattern: '~/.config/gh/', reason: 'GitHub CLI tokens' },
  ],
  high: [
    { pattern: '~/git/', reason: 'Source code repositories' },
    { pattern: '/etc/passwd', reason: 'System user information' },
    { pattern: '~/.config/', reason: 'Application configs may contain tokens' },
    { pattern: '.env', reason: 'Environment files with secrets' },
    { pattern: '*.pem', reason: 'SSL/TLS certificates and keys' },
    { pattern: '*.key', reason: 'Private key files' },
  ],
  medium: [
    { pattern: '~/Documents/', reason: 'Personal documents' },
    { pattern: '~/Desktop/', reason: 'Desktop files' },
    { pattern: '~/Downloads/', reason: 'Downloaded files' },
  ],
  low: [
    { pattern: './', reason: 'Working directory project files' },
    { pattern: 'node_modules/', reason: 'Dependencies (public code)' },
    { pattern: 'dist/', reason: 'Build output' },
  ],
}

export const loadSensitivityMap = trace('loadSensitivityMap', async (): Promise<SensitivityMap> => {
  const overridePath = join(homedir(), '.havik', 'sensitivity.yaml')
  try {
    const text = await readTextOrNull(overridePath)
    if (text === null) return DEFAULTS
    const overrides = yaml.load(text) as Partial<SensitivityMap>
    return {
      critical: [...(overrides.critical ?? []), ...DEFAULTS.critical],
      high: [...(overrides.high ?? []), ...DEFAULTS.high],
      medium: [...(overrides.medium ?? []), ...DEFAULTS.medium],
      low: [...(overrides.low ?? []), ...DEFAULTS.low],
    }
  } catch {
    return DEFAULTS
  }
})

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const PATH_END = `(?=$|[\\s'"):,;])`

const matchesPattern = (path: string, pattern: string): boolean => {
  if (pattern === '.env') return new RegExp(`(?:^|[/\\s'"=])\\.env(?:\\.[\\w.-]+)?${PATH_END}`).test(path)
  if (pattern.startsWith('*.')) return new RegExp(`${escapeRegExp(pattern.slice(1))}${PATH_END}`, 'i').test(path)
  return path.includes(pattern.replace('~', ''))
}

export const classifyPath = trace('classifyPath', (path: string, map: SensitivityMap): { level: SensitivityLevel; reason: string } => {
  for (const level of ['critical', 'high', 'medium', 'low'] as const) {
    for (const entry of map[level]) {
      if (matchesPattern(path, entry.pattern)) {
        return { level, reason: entry.reason }
      }
    }
  }
  return { level: 'low', reason: 'No specific classification' }
})
