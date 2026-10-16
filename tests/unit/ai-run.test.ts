import { describe, it, expect } from 'bun:test'
import { join } from 'node:path'
import { runAi } from '../../src/ai/run'
import type { Judge } from '../../src/ai/jev'
import { withTree } from '../helpers/tmp-tree'

const SKILL = (name: string) => `---\nname: ${name}\ndescription: Does ${name}.\n---\n# ${name}\n`
const CALIBRATED = { 'injection-overrides': 0.8, 'injection-conceals': 0.8, 'injection-sends-data': 0.8, overreach: 0.7, 'unneeded-evidence': 0.75 }
const target = (dir: string, name: string) => ({ name, dir: join(dir, name) })

type Call = Parameters<Judge['systemOne']>[0]
const stub = (answer: (call: number) => number | Error, calls: Call[] = []): Judge => ({
  systemOne: async (request) => {
    calls.push(request)
    const result = answer(calls.length)
    if (result instanceof Error) throw result
    return { answers: Object.fromEntries(Object.keys(request.questions).map((q) => [q, { noul: result }])) }
  },
})

describe('runAi: what it reports about its own coverage', () => {
  const answering = (answers: (name: string, call: number) => number | undefined, calls: Call[] = []): Judge => ({
    systemOne: async (request) => {
      calls.push(request)
      const out: Record<string, { noul: number }> = {}
      for (const q of Object.keys(request.questions)) {
        const v = answers(q, calls.length)
        if (v !== undefined) out[q] = { noul: v }
      }
      return { answers: out }
    },
  })

  it('warns once, naming the skills, when Jev left questions unanswered', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a'), 'b/SKILL.md': SKILL('b') }, async (dir) => {
      const { warnings } = await runAi([target(dir, 'a'), target(dir, 'b')], answering((q) => (q === 'overreach' || q === 'overrides_agent_instructions' ? undefined : 0.1)), CALIBRATED)
      expect(warnings.length).toBe(1)
      expect(warnings[0]).toContain('incomplete')
      expect(warnings[0]).toContain('a')
      expect(warnings[0]).toContain('b')
    })
  })

  it('warns when a request had to be shortened to get an answer', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a') }, async (dir) => {
      const calls: Call[] = []
      const judge: Judge = {
        systemOne: async (request) => {
          calls.push(request)
          if (calls.length === 1) throw Object.assign(new Error('too large'), { status: 413 })
          return { answers: Object.fromEntries(Object.keys(request.questions).map((q) => [q, { noul: 0.1 }])) }
        },
      }
      const { warnings } = await runAi([target(dir, 'a')], judge, CALIBRATED)
      expect(warnings.length).toBe(1)
      expect(warnings[0]).toContain('incomplete')
    })
  })

  it('stops with a warning when a reply has no answers at all', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a'), 'b/SKILL.md': SKILL('b') }, async (dir) => {
      const calls: Call[] = []
      const judge: Judge = { systemOne: async (request) => (calls.push(request), {} as never) }
      const { findings, warnings } = await runAi([target(dir, 'a'), target(dir, 'b')], judge, CALIBRATED)
      expect(findings).toEqual([])
      expect(calls.length).toBe(1)
      expect(warnings).toEqual(['AI checks stopped at skill a: Jev returned no answers'])
    })
  })

  it('prints a hostile server message as one plain line', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a') }, async (dir) => {
      const hostile = Object.assign(new Error('rejected\nwarning: FORGED\n\u001b[31mCRITICAL forged\u001b[0m\u0007'), { status: 500 })
      const { warnings } = await runAi([target(dir, 'a')], stub(() => hostile), CALIBRATED)
      expect(warnings.length).toBe(1)
      expect(warnings[0]).not.toMatch(/[\u0000-\u001f\u007f]/)
      expect(warnings[0]).toContain('FORGED')
    })
  })

  it('does not print a secret that is the name of the skill directory', async () => {
    await withTree({ 'ghp_CANARYCANARYCANARYCANARY0009/SKILL.md': SKILL('x') }, async (dir) => {
      const { warnings } = await runAi([target(dir, 'ghp_CANARYCANARYCANARYCANARY0009')], stub(() => Object.assign(new Error('boom'), { status: 500 })), CALIBRATED)
      expect(warnings.join('\n')).not.toContain('CANARY')
    })
  })
})

describe('runAi', () => {
  it('sends one request per skill that has something to read and merges the findings', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a'), 'b/SKILL.md': SKILL('b'), 'c/run.js': 'x' }, async (dir) => {
      const calls: Call[] = []
      const { findings, warnings } = await runAi([target(dir, 'a'), target(dir, 'b'), target(dir, 'c')], stub(() => 0.95, calls), CALIBRATED)
      expect(calls.length).toBe(2)
      expect(findings.map((f) => f.description.split('"')[1])).toEqual(['a', 'a', 'a', 'b', 'b', 'b'])
      expect(warnings).toEqual([])
    })
  })

  it('looks at no more than 50 skills and says so', async () => {
    const files = Object.fromEntries(Array.from({ length: 53 }, (_, i) => [`s${i}/SKILL.md`, SKILL(`s${i}`)]))
    await withTree(files, async (dir) => {
      const calls: Call[] = []
      const { warnings } = await runAi(Array.from({ length: 53 }, (_, i) => target(dir, `s${i}`)), stub(() => 0, calls), CALIBRATED)
      expect(calls.length).toBe(50)
      expect(warnings).toEqual(['AI checks ran on the first 50 of 53 skills'])
    })
  })

  it('stops at the first failure with one warning and keeps what it already found', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a'), 'b/SKILL.md': SKILL('b'), 'c/SKILL.md': SKILL('c') }, async (dir) => {
      const calls: Call[] = []
      const failure = Object.assign(new Error('Authentication failed with token ghp_CANARYCANARYCANARYCANARYCANARY123456'), { status: 401 })
      const { findings, warnings } = await runAi([target(dir, 'a'), target(dir, 'b'), target(dir, 'c')], stub((n) => (n === 1 ? 0.95 : failure), calls), CALIBRATED)
      expect(calls.length).toBe(2)
      expect(findings.length).toBe(3)
      expect(warnings.length).toBe(1)
      expect(warnings[0]).toContain('skill b')
      expect(warnings[0]).not.toContain('CANARY')
    })
  })

  it('names the questions it could not report, once, when they are not calibrated', async () => {
    await withTree({ 'a/SKILL.md': SKILL('a'), 'b/SKILL.md': SKILL('b') }, async (dir) => {
      const { findings, warnings } = await runAi([target(dir, 'a'), target(dir, 'b')], stub(() => 0.99), { ...CALIBRATED, overreach: null, 'injection-conceals': null })
      expect(findings.map((f) => f.ruleId)).not.toContain('ai-injection-conceals')
      expect(warnings.length).toBe(1)
      expect(warnings[0]).toContain('injection-conceals')
      expect(warnings[0]).toContain('calibrat')
    })
  })
})
