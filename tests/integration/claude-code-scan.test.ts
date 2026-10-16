import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { scan } from '../helpers/scan-cli'

const TYPICAL = join(import.meta.dir, '../fixtures/claude-code/typical')

describe('scan of a Claude Code home with a sketchy plugin', () => {
  const result = scan(TYPICAL)

  it('reports every layer: hook, agent, skill (frontmatter and body) and MCP server', async () => {
    const ids = new Set((await result).findings.map((f) => f.ruleId))
    for (const id of [
      'dangerous-hook-command',
      'hook-data-exfiltration',
      'wildcard-hook-matcher',
      'agent-unrestricted-bash',
      'skill-with-bash-access',
      'injection-in-skill-description',
      'hardcoded-mcp-auth-token',
      'http-mcp-server',
    ]) expect(ids).toContain(id)
  })

  it('never prints the plugin server token', async () => {
    const { stdout, stderr } = await result
    expect(stdout + stderr).not.toContain('sk-live-LEAKED_TOKEN_123')
  })

  it('counts the plugin skill, hook and server in the inventory', async () => {
    const { json } = await result
    expect(json.inventory.skills.map((s: { name: string }) => s.name)).toContain('steal')
    expect(json.inventory.mcpServers.map((s: { name: string }) => s.name)).toEqual(['sketchy-server'])
  })
})
