import { describe, it, expect } from 'bun:test'
import { join } from 'node:path'
import { agentById } from '../../src/agents/registry'
import { makeDb } from '../helpers/sqlite'
import { withTree } from '../helpers/tmp-tree'

const CANARY = 'CANARYCANARY0123456789abcdef'
const setupOf = (id: string, home: string) => agentById(id)!.setup!(home)
const names = (s: { toolServers: readonly { name: string }[] }) => s.toolServers.map((t) => t.name).sort()

describe('setup: tool servers are named, their values never kept', () => {
  it('Claude Code: global and per-project servers, and whether it asks first', async () => {
    const claudeJson = JSON.stringify({ mcpServers: { docs: { command: 'npx', args: ['docs-mcp', '--key', CANARY], env: { API_KEY: `sk-${CANARY}` } } }, projects: { '/p': { mcpServers: { remote: { type: 'http', url: `https://mcp.example.com/sse?token=${CANARY}`, headers: { Authorization: `Bearer ${CANARY}` } } } } } })
    await withTree({ '.claude.json': claudeJson, '.claude/settings.json': JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }) }, async (home) => {
      const s = await setupOf('claude-code', home)
      expect(names(s)).toEqual(['docs', 'remote'])
      expect(s.approvals).toBe('runs without asking')
      expect(s.toolServers.find((t) => t.name === 'remote')?.url).toBe('mcp.example.com')
      expect(JSON.stringify(s)).not.toContain('CANARY')
    })
  })

  it('Cursor, Gemini CLI and Antigravity: servers from their JSON files', async () => {
    const servers = (n: string) => JSON.stringify({ mcpServers: { [n]: { command: 'npx', env: { TOKEN: CANARY } } } })
    await withTree({ '.cursor/mcp.json': servers('github'), '.gemini/settings.json': servers('search'), '.gemini/config/mcp_config.json': servers('files') }, async (home) => {
      expect(names(await setupOf('cursor', home))).toEqual(['github'])
      expect(names(await setupOf('gemini-cli', home))).toEqual(['search'])
      expect(names(await setupOf('antigravity', home))).toEqual(['files'])
      expect(JSON.stringify(await setupOf('cursor', home))).not.toContain('CANARY')
    })
  })

  it('Codex: servers and the approval policy from config.toml', async () => {
    const toml = `approval_policy = "never"\n[mcp_servers.docs]\ncommand = "npx"\nenv = { TOKEN = "${CANARY}" }\n`
    await withTree({ '.codex/config.toml': toml }, async (home) => {
      const s = await setupOf('codex', home)
      expect([names(s), s.approvals]).toEqual([['docs'], 'runs without asking'])
      expect(JSON.stringify(s)).not.toContain('CANARY')
    })
    await withTree({ '.codex/config.toml': 'approval_policy = "on-request"\n' }, async (home) => expect((await setupOf('codex', home)).approvals).toBe('asks first'))
  })

  it('the Claude desktop app: configured servers and installed extensions', async () => {
    const support = 'Library/Application Support/Claude'
    await withTree({
      [`${support}/claude_desktop_config.json`]: JSON.stringify({ mcpServers: { notes: { command: 'node' } } }),
      [`${support}/extensions-installations.json`]: JSON.stringify({ extensions: { 'ant.dir.ant.anthropic.filesystem': { id: 'x' } } }),
    }, async (home) => expect(names(await setupOf('claude-desktop', home))).toEqual(['filesystem', 'notes']))
  })

  it('Hermes: reachable from the chat apps that started its sessions, its schedules, and its approval mode', async () => {
    await withTree({ '.hermes/config.yaml': 'approvals:\n  mode: manual\n', '.hermes/cron/jobs.json': JSON.stringify({ jobs: [{}, {}, {}] }) }, async (home) => {
      makeDb(join(home, '.hermes/state.db'), "create table sessions(source text); insert into sessions values ('cron'),('cli'),('telegram'),('telegram');")
      const s = await setupOf('hermes', home)
      expect([s.channels, s.schedules, s.approvals]).toEqual([['Telegram'], 3, 'asks first'])
    })
    await withTree({ '.hermes/config.yaml': 'approvals:\n  mode: off\n' }, async (home) => expect((await setupOf('hermes', home)).approvals).toBe('runs without asking'))
  })

  it('OpenClaw: enabled channels and its tool servers', async () => {
    const config = JSON.stringify({ channels: { telegram: { botToken: CANARY }, whatsapp: { enabled: false }, discord: {} }, mcp: { servers: { browser: { command: 'npx' } } } })
    await withTree({ '.openclaw/openclaw.json': config }, async (home) => {
      const s = await setupOf('openclaw', home)
      expect([s.channels, names(s)]).toEqual([['Discord', 'Telegram'], ['browser']])
      expect(JSON.stringify(s)).not.toContain('CANARY')
    })
  })

  it('a settings file it cannot read is a warning, never an empty answer', async () => {
    await withTree({ '.cursor/mcp.json': '{ not json', '.codex/config.toml': '[[[' }, async (home) => {
      expect((await setupOf('cursor', home)).warnings[0]).toContain('mcp.json')
      expect((await setupOf('codex', home)).warnings[0]).toContain('config.toml')
    })
  })

  it('an empty settings file is "not set up", not a warning', async () => {
    await withTree({ '.gemini/config/mcp_config.json': '', '.cursor/mcp.json': '  \n' }, async (home) => {
      expect((await setupOf('antigravity', home)).warnings).toEqual([])
      expect((await setupOf('cursor', home)).warnings).toEqual([])
    })
  })

  it('an agent that is not set up has nothing to report and no warning', async () => {
    await withTree({}, async (home) => {
      for (const id of ['claude-code', 'cursor', 'codex', 'gemini-cli', 'hermes', 'openclaw', 'claude-desktop', 'antigravity']) {
        expect([id, await setupOf(id, home)]).toEqual([id, { toolServers: [], channels: [], schedules: 0, warnings: [] }])
      }
    })
  })
})
