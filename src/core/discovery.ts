import { readdirSync, statSync } from 'node:fs'
import { join } from 'path'
import { trace } from './trace'
import { detectOpenClaw } from '../adapters/openclaw'
import { detectMcp } from '../adapters/mcp'
import { detectClaudeCode } from '../adapters/claude-code'

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.cache', '__pycache__', '.venv'])
const MAX_DEPTH = 5

interface DiscoveredPath {
  readonly path: string
  readonly frameworks: readonly string[]
}

export const findAgentInstalls = trace('findAgentInstalls', async (
  rootPath: string,
  maxDepth: number = MAX_DEPTH
): Promise<readonly DiscoveredPath[]> => {
  const results: DiscoveredPath[] = []
  const visited = new Set<string>()

  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > maxDepth || visited.has(dir)) return
    visited.add(dir)

    const frameworks: string[] = []
    if (await detectClaudeCode(dir)) frameworks.push('claude-code')
    if (await detectOpenClaw(dir)) frameworks.push('openclaw')
    if (await detectMcp(dir)) frameworks.push('mcp')

    if (frameworks.length > 0) {
      results.push({ path: dir, frameworks })
    }

    try {
      const entries = readdirSync(dir, { withFileTypes: true })
      for (const entry of entries) {
        if (!entry.isDirectory() || entry.name.startsWith('.') && entry.name !== '.claude') continue
        if (SKIP_DIRS.has(entry.name)) continue
        await walk(join(dir, entry.name), depth + 1)
      }
    } catch {
      // permission denied or unreadable — skip
    }
  }

  await walk(rootPath, 0)
  return results
})
