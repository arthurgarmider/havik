import { isAbsolute, join } from 'path'
import { trace } from '../core/trace'
import { fileExists, findFiles, readText, readTextOrNull } from '../core/fs'
import { asArray, asRecord, toList } from '../core/json'
import { splitFrontmatter } from '../core/frontmatter'
import { isInside } from '../core/paths'
import { parseMcpServers } from './mcp'
import type {
  ClaudeCodeInventory, PluginInfo, HookInfo, AgentDefInfo,
  SkillDefInfo, PermissionEntry, McpServerInfo, Result,
} from '../core/types'

const NOT_FOUND = 'not found'
const SETTINGS_FILES = ['settings.json', 'settings.local.json']

const readJson = async (path: string): Promise<Result<any>> => {
  const text = await readTextOrNull(path)
  if (text === null) return { ok: false, error: NOT_FOUND }
  try {
    return { ok: true, value: JSON.parse(text) }
  } catch (e) { return { ok: false, error: String(e) } }
}

const collectHooks = (hooksByEvent: unknown, source: string): HookInfo[] =>
  Object.entries(asRecord(hooksByEvent)).flatMap(([event, matchers]) =>
    asArray(matchers).flatMap((m: any) =>
      asArray(m?.hooks).map((h: any): HookInfo => ({
        event, matcher: m.matcher ?? '', command: String(h?.command ?? ''),
        source, async: h?.async ?? false, timeout: h?.timeout ?? 30,
      }))))

export const detectClaudeCode = trace('detectClaudeCode', async (basePath: string): Promise<boolean> => {
  for (const file of SETTINGS_FILES) {
    if (await fileExists(join(basePath, '.claude', file))) return true
  }
  return false
})

export const discoverClaudeCode = trace('discoverClaudeCode', async (basePath: string): Promise<Result<ClaudeCodeInventory>> => {
  try {
    const claudeDir = join(basePath, '.claude')
    const warnings: string[] = []

    // Frontmatter that is not valid YAML still leaves a skill or agent to analyse; only its metadata is lost.
    const frontmatterOf = (path: string, content: string): Record<string, unknown> => {
      try {
        return splitFrontmatter(content).data
      } catch (e) {
        warnings.push(`Could not read the frontmatter of ${path}: ${e}`)
        return {}
      }
    }

    const settingsFiles = await Promise.all(SETTINGS_FILES.map(async file => ({ path: join(claudeDir, file), data: await readJson(join(claudeDir, file)) })))
    for (const { path, data } of settingsFiles) {
      if (!data.ok && data.error !== NOT_FOUND) warnings.push(`Could not parse ${path}: ${data.error}`)
    }
    const settings = settingsFiles[0].data
    const enabledPlugins = asRecord(settings.ok ? settings.value?.enabledPlugins : undefined)

    const installed = await readJson(join(claudeDir, 'plugins/installed_plugins.json'))
    if (!installed.ok && installed.error !== NOT_FOUND) warnings.push(`Could not parse ${join(claudeDir, 'plugins/installed_plugins.json')}: ${installed.error}`)
    const blocklist = await readJson(join(claudeDir, 'plugins/blocklist.json'))
    const blockedNames = new Set(asArray(blocklist.ok ? blocklist.value?.plugins : []).map((b: any) => b?.plugin))

    const plugins: PluginInfo[] = []
    const hooks: HookInfo[] = []
    const skills: SkillDefInfo[] = []
    const mcpServers: McpServerInfo[] = []

    if (installed.ok) {
      for (const [id, entries] of Object.entries(asRecord(installed.value?.plugins))) {
        const [name, marketplace] = id.split('@')
        const entry = asArray(entries)[0]
        const rawPath = entry?.installPath
        if (typeof rawPath !== 'string') {
          warnings.push(`Skipped plugin ${id}: installed_plugins.json gives it no installPath`)
          continue
        }
        const installPath = isAbsolute(rawPath) ? rawPath : join(claudeDir, rawPath)
        if (!isInside(claudeDir, installPath)) {
          warnings.push(`Skipped plugin ${id}: its installPath ${rawPath} is outside ${claudeDir}`)
          continue
        }

        plugins.push({
          name, marketplace: marketplace ?? 'unknown',
          version: entry.version ?? 'unknown', installPath,
          gitSha: entry.gitCommitSha, enabled: !!enabledPlugins[id],
          blocked: blockedNames.has(id),
        })

        // Discover hooks
        const hooksData = await readJson(join(installPath, 'hooks/hooks.json'))
        if (hooksData.ok) hooks.push(...collectHooks(hooksData.value?.hooks, name))

        // Discover skills
        for (const path of await findFiles('skills/*/SKILL.md', installPath)) {
          const file = join(installPath, path)
          const fm = frontmatterOf(file, await readText(file))
          skills.push({ name: String(fm['name'] ?? path), path: file, allowedTools: toList(fm['allowed-tools']), pluginSource: name })
        }

        // Discover MCP servers
        const mcpPath = join(installPath, '.mcp.json')
        const mcpText = await readTextOrNull(mcpPath)
        if (mcpText !== null) {
          try {
            const data = JSON.parse(mcpText)
            mcpServers.push(...parseMcpServers(mcpPath, mcpText, data.mcpServers ?? data))
          } catch (e) {
            warnings.push(`Could not parse ${mcpPath}: ${e}`)
          }
        }
      }
    }

    // Discover agents
    const agents: AgentDefInfo[] = []
    const agentsDir = join(claudeDir, 'agents')
    for (const path of await findFiles('*.md', agentsDir)) {
      const file = join(agentsDir, path)
      const fm = frontmatterOf(file, await readText(file))
      agents.push({ name: String(fm['name'] ?? path), path: file, tools: toList(fm['tools']), model: typeof fm['model'] === 'string' ? fm['model'] : undefined })
    }

    // Project settings: hooks, permissions and the MCP auto-approve flag
    const permissions: PermissionEntry[] = []
    let autoApproveProjectMcp: string | undefined
    let hooksDisabledBy: string | undefined
    for (const { path, data } of settingsFiles) {
      if (!data.ok) continue
      hooks.push(...collectHooks(data.value?.hooks, path))
      for (const p of asArray(data.value?.permissions?.allow)) permissions.push({ pattern: String(p), source: path })
      if (data.value?.enableAllProjectMcpServers === true) autoApproveProjectMcp ??= path
      if (data.value?.disableAllHooks === true) hooksDisabledBy ??= path
    }

    return { ok: true, value: { plugins, hooks, agents, skills, permissions, mcpServers, autoApproveProjectMcp, hooksDisabledBy, warnings } }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})
