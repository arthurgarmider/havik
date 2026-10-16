import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, dirname, join, relative } from 'node:path'
import { splitFrontmatter } from '../core/frontmatter'
import { readTextOrNull } from '../core/fs'
import type { SensitivityMap } from '../core/sensitivity'
import { isDangerousExec } from '../core/shell-patterns'
import { VERSION } from '../version'
import { tildify } from './accesses'
import { havikHome } from './policy'
import type { GuardFinding } from './types'

const MAX_SCRIPT = 1_000_000

// Line numbers of what the static scan found; `version` invalidates the cache when havik changes.
interface Evidence {
  readonly version: string
  readonly strongSource?: number
  readonly sink?: number
  readonly host?: string
  readonly obfuscated?: number
  readonly obfuscatedName?: string
  readonly dangerous?: number
}

const cacheFile = (sha: string): string => join(havikHome(), 'cache', 'jit', `${sha}.json`)

const readCache = async (sha: string): Promise<Evidence | undefined> => {
  try {
    const cached = JSON.parse((await readTextOrNull(cacheFile(sha))) ?? 'null') as Evidence | null
    return cached?.version === VERSION ? cached : undefined
  } catch {
    return undefined
  }
}

const writeCache = async (sha: string, evidence: Evidence): Promise<Evidence> => {
  await mkdir(dirname(cacheFile(sha)), { recursive: true, mode: 0o700 }).catch(() => undefined)
  await writeFile(cacheFile(sha), JSON.stringify(evidence), { mode: 0o600 }).catch(() => undefined)
  return evidence
}

// The AST engine is loaded here and only here, so a hook call that runs no script never evaluates it.
const analyse = async (path: string, text: string, map: SensitivityMap): Promise<Evidence> => {
  const { evidenceFor } = await import('../core/skill-analyzer')
  const e = evidenceFor(path, text, false, map)
  const dangerous = text.split('\n').findIndex(line => isDangerousExec(line))
  return {
    version: VERSION,
    strongSource: e.sources.find(s => s.strong)?.line,
    sink: e.sinks[0]?.line,
    host: e.sinks[0]?.host,
    obfuscated: e.obfuscated[0]?.line,
    obfuscatedName: e.obfuscated[0]?.name,
    dangerous: dangerous >= 0 ? dangerous + 1 : undefined,
  }
}

// The nearest SKILL.md above the script names the skill; the search stops at the home directory.
const skillOf = async (script: string, home: string): Promise<{ name: string; dir: string } | undefined> => {
  for (let dir = dirname(script); dir !== dirname(dir) && dir !== home; dir = dirname(dir)) {
    const text = await readTextOrNull(join(dir, 'SKILL.md'))
    if (text === null) continue
    let name: unknown
    try {
      name = splitFrontmatter(text).data['name']
    } catch {
      name = undefined
    }
    return { name: typeof name === 'string' && name.trim() ? name.trim().slice(0, 80) : basename(dir), dir }
  }
  return undefined
}

const verdict = (e: Evidence): { severity: 'critical' | 'high'; what: string; line: number } | undefined => {
  if (e.strongSource && e.sink) return { severity: 'critical', what: `reads credentials (line ${e.strongSource}) and sends data to ${e.host ?? 'an outside host'} (line ${e.sink})`, line: e.sink }
  if (e.dangerous) return { severity: 'critical', what: `downloads code and runs it (line ${e.dangerous})`, line: e.dangerous }
  if (e.strongSource) return { severity: 'high', what: `reads credentials (line ${e.strongSource})`, line: e.strongSource }
  if (e.obfuscated) return { severity: 'high', what: `builds the name ${e.obfuscatedName ?? 'of a sensitive API'} at runtime (line ${e.obfuscated})`, line: e.obfuscated }
  return undefined
}

export const scanScript = async (path: string, map: SensitivityMap, home: string): Promise<GuardFinding | null> => {
  const info = await lstat(path).catch(() => null)
  if (!info || !info.isFile() || info.size > MAX_SCRIPT) return null
  const text = await readFile(path, 'utf8')
  const sha = createHash('sha256').update(text).digest('hex')
  const evidence = (await readCache(sha)) ?? (await writeCache(sha, await analyse(path, text, map)))
  const v = verdict(evidence)
  if (!v) return null
  const skill = await skillOf(path, home)
  const where = relative(skill?.dir ?? dirname(path), path)
  const owner = skill ? ` of skill ${skill.name}` : ''
  return {
    detector: 'script-about-to-run', severity: v.severity, key: `script-about-to-run:${sha}`,
    message: `${where}${owner} ${v.what}`, label: `run ${tildify(path, home)}`, kind: 'script',
    script: path, skill: skill?.name, evidence: 'static', proof: `${where}:${v.line}`,
  }
}
