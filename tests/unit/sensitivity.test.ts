import { test, expect, describe } from 'bun:test'
import { classifyPath, loadSensitivityMap } from '../../src/core/sensitivity'
import type { SensitivityMap } from '../../src/core/sensitivity'

const DEFAULT_MAP: SensitivityMap = {
  critical: [
    { pattern: '~/.ssh/', reason: 'SSH private keys' },
    { pattern: 'process.env', reason: 'Environment variables with API keys and tokens' },
    { pattern: '~/.aws/', reason: 'AWS credentials' },
    { pattern: '~/.claude/', reason: 'Claude Code config and session data' },
    { pattern: '~/.gnupg/', reason: 'GPG private keys' },
    { pattern: '~/.kube/', reason: 'Kubernetes credentials' },
    { pattern: '~/.docker/', reason: 'Docker credentials' },
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

describe('sensitivity', () => {
  describe('classifyPath', () => {
    test('classifies SSH paths as critical', () => {
      const result = classifyPath('/.ssh/id_rsa', DEFAULT_MAP)
      expect(result.level).toBe('critical')
      expect(result.reason).toBe('SSH private keys')
    })

    test('classifies process.env as critical', () => {
      const result = classifyPath('process.env', DEFAULT_MAP)
      expect(result.level).toBe('critical')
    })

    test('classifies AWS credentials as critical', () => {
      const result = classifyPath('/.aws/credentials', DEFAULT_MAP)
      expect(result.level).toBe('critical')
    })

    test('classifies git repos as high', () => {
      const result = classifyPath('/git/my-project', DEFAULT_MAP)
      expect(result.level).toBe('high')
    })

    test('classifies .env files as high', () => {
      const result = classifyPath('.env.local', DEFAULT_MAP)
      expect(result.level).toBe('high')
    })

    test('classifies Documents as medium', () => {
      const result = classifyPath('/Documents/tax-return.pdf', DEFAULT_MAP)
      expect(result.level).toBe('medium')
    })

    test('classifies node_modules as low', () => {
      const result = classifyPath('node_modules/lodash/index.js', DEFAULT_MAP)
      expect(result.level).toBe('low')
    })

    test('returns low with default reason for unclassified paths', () => {
      const result = classifyPath('/tmp/random-file.txt', DEFAULT_MAP)
      expect(result.level).toBe('low')
      expect(result.reason).toBe('No specific classification')
    })

    test('.env matches only as a file name, not inside other words', () => {
      expect(classifyPath('/app/.env', DEFAULT_MAP).level).toBe('high')
      expect(classifyPath('/app/config.environment.js', DEFAULT_MAP).level).toBe('low')
      expect(classifyPath('/app/app.envelope', DEFAULT_MAP).level).toBe('low')
    })

    test('*.pem and *.key match as extensions', () => {
      expect(classifyPath('/certs/server.pem', DEFAULT_MAP).level).toBe('high')
      expect(classifyPath('/keys/id.key', DEFAULT_MAP).level).toBe('high')
      expect(classifyPath('/docs/pem-notes.txt', DEFAULT_MAP).level).toBe('low')
    })

    test('matches higher severity first when multiple patterns match', () => {
      const result = classifyPath('/.claude/settings.json', DEFAULT_MAP)
      expect(result.level).toBe('critical')
    })
  })

  describe('loadSensitivityMap', () => {
    test('returns default map when no override file exists', async () => {
      const map = await loadSensitivityMap()
      expect(map.critical.length).toBeGreaterThanOrEqual(7)
      expect(map.high.length).toBeGreaterThanOrEqual(6)
      expect(map.medium.length).toBeGreaterThanOrEqual(3)
      expect(map.low.length).toBeGreaterThanOrEqual(3)
    })
  })
})

describe('default sensitivity map covers what the shell patterns cover', () => {
  test('classifies common credential files as critical', async () => {
    const map = await loadSensitivityMap()
    for (const path of ['~/.ssh/id_rsa', '/home/u/.ssh/id_ed25519', '/home/u/.npmrc', '/home/u/.netrc', '/home/u/.pypirc', '/home/u/.git-credentials', '/etc/shadow', '~/.aws/credentials', '~/.kube/config', '~/.gnupg/secring.gpg']) {
      expect({ path, level: classifyPath(path, map).level }).toEqual({ path, level: 'critical' })
    }
  })
})

