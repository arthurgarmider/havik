import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { readFileSync } from 'fs'
import { scan, FIXTURES, type ScanFinding } from '../helpers/scan-cli'

const ATTACKS = join(FIXTURES, 'attacks')
const BENIGN = join(FIXTURES, 'benign')

const lineOf = (file: string, needle: string): number =>
  readFileSync(file, 'utf8').split('\n').findIndex((l) => l.includes(needle)) + 1
const ruleIds = (findings: readonly ScanFinding[]) => findings.map((f) => f.ruleId)
const inFile = (findings: readonly ScanFinding[], suffix: string) => findings.filter((f) => f.proof?.file.endsWith(suffix))
const forServer = (findings: readonly ScanFinding[], name: string) => findings.filter((f) => f.description.includes(`"${name}"`))

describe('skill-exfil: bare skill that steals ~/.ssh/id_rsa', () => {
  const dir = join(ATTACKS, 'skill-exfil')
  const result = scan(dir)

  it('reports the read + POST as a critical credential-exfiltration with file:line proof', async () => {
    const r = await result
    const run = join(dir, 'scripts/run.js')
    const evidenceLines = [lineOf(run, 'id_rsa'), lineOf(run, 'fetch('), lineOf(run, 'execSync(')]
    const finding = inFile(r.findings, 'scripts/run.js').find((f) => f.ruleId === 'credential-exfiltration')
    expect(ruleIds(r.findings)).toContain('credential-exfiltration')
    expect(finding?.severity).toBe('critical')
    expect(evidenceLines).toContain(finding?.proof?.line as number)
  })

  it('cites the line of the shell helper that posts the key with curl', async () => {
    const r = await result
    const helper = inFile(r.findings, 'scripts/helper.sh')
    expect(helper.map((f) => `${f.ruleId}:${f.proof?.line}`)).toContain('credential-exfiltration:2')
  })

  it('grades below A and exits 2', async () => {
    const r = await result
    expect(r.grade).not.toBe('A')
    expect(r.code).toBe(2)
  })
})

describe('repo-hook-mcp: project settings + .mcp.json attack', () => {
  const result = scan(join(ATTACKS, 'repo-hook-mcp'))

  it('flags the curl|bash SessionStart hook, Bash(*) and enableAllProjectMcpServers', async () => {
    const ids = ruleIds((await result).findings)
    expect(ids).toContain('dangerous-hook-command')
    expect(ids).toContain('overly-permissive-bash')
    expect(ids).toContain('mcp-enable-all-project-servers')
  })

  it('flags the .mcp.json command that pipes the SSH key to curl exactly once', async () => {
    const cmd = (await result).findings.filter((f) => f.ruleId === 'mcp-dangerous-command')
    expect(cmd.map((f) => f.severity)).toEqual(['critical'])
    expect(cmd[0].description).toContain('"helper"')
  })

  it('grades below A and exits 2', async () => {
    const r = await result
    expect(r.grade).not.toBe('A')
    expect(r.code).toBe(2)
  })
})

describe('mcp-commands: one finding class per server command line', () => {
  const result = scan(join(ATTACKS, 'mcp-commands'))
  const ruleFor = async (server: string) => forServer((await result).findings, server).map((f) => `${f.ruleId}:${f.severity}`)

  it('unpinned npx -y is low', async () => expect(await ruleFor('unpinned-npx')).toEqual(['mcp-unpinned-package:low']))
  it('pinned npx -y is clean', async () => expect(await ruleFor('pinned-npx')).toEqual([]))
  it('curl | sh is critical', async () => expect(await ruleFor('curl-pipe-sh')).toEqual(['mcp-dangerous-command:critical']))
  it('python -c is medium', async () => expect(await ruleFor('inline-python')).toEqual(['mcp-inline-code:medium']))
  it('a server merely named *secret-manager* with --env-file is clean', async () => expect(await ruleFor('env-file-flag')).toEqual([]))

  it('a literal env secret is flagged by key name only', async () => {
    const hits = forServer((await result).findings, 'env-secret').filter((f) => f.ruleId === 'hardcoded-mcp-env-secret')
    expect(hits.length).toBe(1)
    expect(hits[0].proof?.snippet).toContain('API_KEY=[REDACTED]')
  })

  it('no raw secret from env, args or url reaches the output', async () => {
    const { stdout, stderr } = await result
    for (const secret of ['sk-live-abcdef1234567890', 'pw123456', 'tok_abcdef123456']) {
      expect(stdout).not.toContain(secret)
      expect(stderr).not.toContain(secret)
    }
  })
})

describe('benign controls stay quiet', () => {
  for (const name of ['python', 'js', 'api-skill']) {
    it(`${name}: no high or critical findings, exit 0`, async () => {
      const r = await scan(join(BENIGN, name))
      const loud = r.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')
      expect(loud.map((f) => `${f.ruleId}@${f.proof?.file}`)).toEqual([])
      expect(r.code).toBe(0)
    })
  }

  it('aws-skill: declared network+credentials is never critical', async () => {
    const r = await scan(join(BENIGN, 'aws-skill'))
    expect(r.findings.filter((f) => f.severity === 'critical').map((f) => f.ruleId)).toEqual([])
  })
})
