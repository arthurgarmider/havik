import { join } from 'path'
import { trace } from '../core/trace'
import { findFiles, readText } from '../core/fs'
import type { Finding, Result } from '../core/types'

const SECRET_PATTERNS = /(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)\s*=\s*\S+/i
const BIND_ALL_PATTERN = /0\.0\.0\.0/
const CREDENTIAL_GLOB_PATTERNS = ['**/*.key', '**/*.pem']

let findingCounter = 0
const nextId = (prefix: string) => `${prefix}-${String(++findingCounter).padStart(3, '0')}`

export const detectGeneric = (): boolean => true

async function checkEnvFiles(basePath: string): Promise<Finding[]> {
  const findings: Finding[] = []

  for (const rel of await findFiles('**/{.env,.env.*}', basePath, { dot: true })) {
    const filePath = join(basePath, rel)
    const text = await readText(filePath)
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      if (SECRET_PATTERNS.test(lines[i])) {
        findings.push({
          id: nextId('GEN'),
          ruleId: 'env-secret-exposure',
          severity: 'high',
          confidence: 'high',
          owasp: 'ASI03',
          description: `Secret detected in ${rel}`,
          proof: {
            file: filePath,
            line: i + 1,
            snippet: lines[i].replace(/=.+/, '=***'),
            safeToDisplay: true,
          },
        })
        break
      }
    }
  }

  return findings
}

async function checkBindAddresses(basePath: string): Promise<Finding[]> {
  const findings: Finding[] = []

  for (const rel of await findFiles('**/*.{json,yaml,yml,toml,conf,cfg}', basePath, { dot: true })) {
    const filePath = join(basePath, rel)
    const text = await readText(filePath)
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      if (BIND_ALL_PATTERN.test(lines[i])) {
        findings.push({
          id: nextId('GEN'),
          ruleId: 'bind-all-interfaces',
          severity: 'medium',
          confidence: 'high',
          owasp: 'ASI05',
          description: `Config binds to all interfaces in ${rel}`,
          proof: {
            file: filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            safeToDisplay: true,
          },
        })
        break
      }
    }
  }

  return findings
}

async function checkCredentialFiles(basePath: string): Promise<Finding[]> {
  const findings: Finding[] = []

  for (const pattern of CREDENTIAL_GLOB_PATTERNS) {
    for (const rel of await findFiles(pattern, basePath, { dot: true })) {
      if (rel.startsWith('.ssh/') || rel.startsWith('certs/')) continue
      const filePath = join(basePath, rel)
      findings.push({
        id: nextId('GEN'),
        ruleId: 'credential-file-exposed',
        severity: 'high',
        confidence: 'medium',
        owasp: 'ASI03',
        description: `Credential file found at non-standard location: ${rel}`,
        proof: {
          file: filePath,
          line: 1,
          snippet: rel,
          safeToDisplay: true,
        },
      })
    }
  }

  return findings
}

export const analyzeGeneric = trace(
  'analyzeGeneric',
  async (basePath: string): Promise<Result<readonly Finding[]>> => {
    try {
      findingCounter = 0
      const [envFindings, bindFindings, credFindings] = await Promise.all([
        checkEnvFiles(basePath),
        checkBindAddresses(basePath),
        checkCredentialFiles(basePath),
      ])
      return { ok: true, value: [...envFindings, ...bindFindings, ...credFindings] }
    } catch (error) {
      return { ok: false, error: `Generic analysis failed: ${error}` }
    }
  }
)
