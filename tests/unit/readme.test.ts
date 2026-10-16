import { describe, it, expect } from 'bun:test'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { findFiles } from '../../src/core/fs'

const ROOT = join(import.meta.dir, '../..')
const readme = readFileSync(join(ROOT, 'README.md'), 'utf8')

const idsInSource = async (): Promise<string[]> =>
  (await findFiles('**/*.ts', join(ROOT, 'src'), { absolute: true })).flatMap(f =>
    [...readFileSync(f, 'utf8').matchAll(/ruleId:\s*'([a-z][a-z0-9-]*)'/g)].map(m => m[1]))

const idsInRules = (): string[] =>
  readdirSync(join(ROOT, 'rules/core')).flatMap(f =>
    [...readFileSync(join(ROOT, 'rules/core', f), 'utf8').matchAll(/^id:\s*(\S+)/gm)].map(m => m[1]))

describe('README honesty', () => {
  it('names every rule id the code can emit', async () => {
    const all = new Set([...(await idsInSource()), ...idsInRules()])
    expect([...all].filter(id => !readme.includes(`\`${id}\``)).sort()).toEqual([])
  })

  it('lists no rule that does not exist', async () => {
    const real = new Set([...(await idsInSource()), ...idsInRules()])
    const section = readme.slice(readme.indexOf('## Rules'), readme.indexOf('## Known gaps'))
    const listed = [...section.matchAll(/^\| `([a-z0-9-]+)`/gm)].map(m => m[1])
    expect(listed.length).toBeGreaterThan(20)
    expect(listed.filter(id => !real.has(id))).toEqual([])
  })

  it('does not describe features that were removed or never built', () => {
    expect(readme).not.toMatch(/havik (fix|badge|report|config)|--deep|LangChain|havik\.dev|attest|OWASP coverage|low false-positive/i)
  })

  it('says plainly that --ai is the only thing that uses the network, and what it sends', () => {
    expect(readme).toMatch(/`--ai`[^\n]*off by default|off by default[^\n]*`--ai`/i)
    for (const fact of ['api.typesafe.ai', 'TYPESAFE_API_KEY', 'redacted', 'never removes']) expect(readme).toContain(fact)
    expect(readme).not.toMatch(/nothing is sent anywhere|no network access, no LLM/i)
  })

  it('names every guard detector and says the guard never blocks', () => {
    const types = readFileSync(join(ROOT, 'src/guard/types.ts'), 'utf8')
    const union = types.match(/export type Detector = ([^\n]+)/)?.[1] ?? ''
    const detectors = [...union.matchAll(/'([a-z-]+)'/g)].map((m) => m[1])
    expect(detectors.length).toBe(5)
    expect(detectors.filter((d) => !readme.includes(`\`${d}\``))).toEqual([])
    expect(readme).toMatch(/^## Runtime guard/m)
    expect(readme).toContain('never blocks')
  })

  it('has a Known gaps section', () => {
    expect(readme).toMatch(/^## Known gaps$/m)
  })
})
