import { describe, it, expect } from 'bun:test'
import { judgeSkill, type Fact, type Judge, type SkillBrief } from '../../src/ai/jev'

const DIR = '/home/alice/skills/s'
const brief = (over: Partial<SkillBrief> = {}): SkillBrief => ({
  name: 's', dir: DIR, file: `${DIR}/SKILL.md`, description: 'Formats dates', body: '# s\nFormats dates.', facts: [], ...over,
})
const fact = (line: number, strong = false, text = `reads /root/.ssh/id_rsa #${line}`): Fact => ({ text, file: `${DIR}/scripts/run.js`, line, strong })

const THRESHOLDS = { 'injection-overrides': 0.8, 'injection-conceals': 0.8, 'injection-sends-data': 0.8, overreach: 0.7, 'unneeded-evidence': 0.75 }

type Request = Parameters<Judge['systemOne']>[0]
// A judge that answers each question with the probability the test chooses; undefined means no answer.
const judgeWith = (p: (name: string) => number | undefined, calls: Request[] = []): Judge => ({
  systemOne: async (request) => {
    calls.push(request)
    const answers: Record<string, { noul: number }> = {}
    for (const name of Object.keys(request.questions)) {
      const value = p(name)
      if (value !== undefined) answers[name] = { noul: value }
    }
    return { answers }
  },
})
const ruleIds = async (judge: Judge, b = brief(), thresholds = THRESHOLDS) => (await judgeSkill(judge, b, thresholds)).findings.map((f) => f.ruleId)

describe('what is asked', () => {
  it('asks the three injection questions in one request, and adds overreach plus one question per fact when there are facts', async () => {
    const calls: Request[] = []
    await judgeSkill(judgeWith(() => 0, calls), brief(), THRESHOLDS)
    expect(calls.length).toBe(1)
    expect(Object.keys(calls[0].questions)).toEqual(['overrides_agent_instructions', 'conceals_actions_from_user', 'instructs_sending_data_off_machine'])

    const withFacts: Request[] = []
    await judgeSkill(judgeWith(() => 0, withFacts), brief({ facts: [fact(1), fact(2)] }), THRESHOLDS)
    expect(Object.keys(withFacts[0].questions)).toEqual(['overrides_agent_instructions', 'conceals_actions_from_user', 'instructs_sending_data_off_machine', 'overreach', 'unneeded_1', 'unneeded_2'])
    expect(Object.values(withFacts[0].questions).every((q) => q.type === 'noul' && q.instructions.length > 20)).toBe(true)
  })

  it('sends at most 8 facts, each on one line, and never more than 8 KB', async () => {
    const calls: Request[] = []
    const long = `${'x '.repeat(400)}\nsecond line`
    await judgeSkill(judgeWith(() => 0, calls), brief({ body: 'word '.repeat(20_000), facts: Array.from({ length: 12 }, (_, i) => fact(i + 1, false, long)) }), THRESHOLDS)
    const state = calls[0].state as { facts: string[] }
    expect(state.facts.length).toBe(8)
    expect(state.facts.every((f) => !f.includes('\n') && f.length <= 300)).toBe(true)
    expect(Object.keys(calls[0].questions).filter((q) => q.startsWith('unneeded_')).length).toBe(8)
    expect(JSON.stringify(calls[0].state).length).toBeLessThanOrEqual(8000)
  })

  it('leaves out secrets and absolute paths, whatever the skill contains', async () => {
    const canary = 'ghp_CANARYCANARYCANARYCANARYCANARY123456'
    const calls: Request[] = []
    await judgeSkill(judgeWith(() => 0, calls), brief({
      description: `Uses ${canary}`,
      body: `token ${canary}\nBearer CANARYBEARER1234567890\n`,
      facts: [fact(1, true, `fetch(u, { headers: { Authorization: "Bearer ${canary}" } })`)],
    }), THRESHOLDS)
    const sent = JSON.stringify(calls[0].state)
    expect(sent).not.toContain('CANARY')
    expect(sent).not.toContain('/home/alice')
    expect(sent).toContain('scripts/run.js:1')
  })
})

describe('what is reported', () => {
  it('reports a question only when its answer reaches the calibrated threshold', async () => {
    expect(await ruleIds(judgeWith((q) => (q === 'overrides_agent_instructions' ? 0.9 : 0.1)))).toEqual(['ai-injection-overrides'])
    expect(await ruleIds(judgeWith((q) => (q === 'overrides_agent_instructions' ? 0.79 : 0.1)))).toEqual([])
    expect(await ruleIds(judgeWith((q) => (q === 'conceals_actions_from_user' ? 0.8 : 0.1)))).toEqual(['ai-injection-conceals'])
    expect(await ruleIds(judgeWith((q) => (q === 'instructs_sending_data_off_machine' ? 1 : 0)))).toEqual(['ai-injection-sends-data'])
  })

  it('withholds the answers of a question that has no calibration, and names it', async () => {
    const verdict = await judgeSkill(judgeWith(() => 0.99), brief({ facts: [fact(1)] }), { ...THRESHOLDS, 'injection-overrides': null, overreach: null })
    expect(verdict.findings.map((f) => f.ruleId)).not.toContain('ai-injection-overrides')
    expect(verdict.findings.map((f) => f.ruleId)).not.toContain('ai-overreach')
    expect(verdict.uncalibrated.sort()).toEqual(['injection-overrides', 'overreach'])
  })

  it('caps AI-only findings at high, and gives critical only to a fact static analysis already rated strong', async () => {
    const found = (await judgeSkill(judgeWith(() => 0.95), brief({ facts: [fact(6, true), fact(9, false)] }), THRESHOLDS)).findings
    const by = (id: string) => found.filter((f) => f.ruleId === id)
    expect(by('ai-injection-overrides')[0].severity).toBe('high')
    expect(by('ai-overreach')[0].severity).toBe('medium')
    expect(by('ai-unneeded-evidence').map((f) => `${f.severity}@${f.proof?.line}`)).toEqual(['critical@6', 'high@9'])
    expect(by('ai-unneeded-evidence')[0].proof?.file).toBe(`${DIR}/scripts/run.js`)
  })

  it('derives confidence from how far the answer is past the threshold', async () => {
    const conf = async (p: number) => (await judgeSkill(judgeWith((q) => (q === 'overrides_agent_instructions' ? p : 0)), brief(), THRESHOLDS)).findings[0].confidence
    expect([await conf(0.99), await conf(0.88), await conf(0.81)]).toEqual(['high', 'medium', 'low'])
  })

  it('ignores an answer that is missing, not a number, or outside 0 to 1', async () => {
    for (const bad of [undefined, Number.NaN, 2, -1, Infinity]) expect(await ruleIds(judgeWith(() => bad))).toEqual([])
    const odd: Judge = { systemOne: async () => ({ answers: { overrides_agent_instructions: { noul: '0.99' as unknown as number }, other: { noul: 1 } } }) }
    expect(await ruleIds(odd)).toEqual([])
  })

  it('names the questions that got no usable answer instead of treating them as a clean result', async () => {
    const partial = judgeWith((q) => (q === 'conceals_actions_from_user' ? undefined : q === 'overreach' ? Number.NaN : 0.1))
    const verdict = await judgeSkill(partial, brief({ facts: [fact(1)] }), THRESHOLDS)
    expect(verdict.unanswered.sort()).toEqual(['conceals_actions_from_user', 'overreach'])
    expect(verdict.shortened).toBe(false)
    expect((await judgeSkill(judgeWith(() => 0.1), brief(), THRESHOLDS)).unanswered).toEqual([])
  })

  it('treats a reply without an answers object as a failure', async () => {
    for (const reply of [{}, { answers: null }, { answers: 'hello' }, null, 'hello', [1, 2, 3]]) {
      const judge: Judge = { systemOne: async () => reply as never }
      await expect(judgeSkill(judge, brief(), THRESHOLDS)).rejects.toThrow('no answers')
    }
  })
})

describe('when the request fails', () => {
  const failing = (statuses: number[], calls: Request[] = []): Judge => ({
    systemOne: async (request) => {
      calls.push(request)
      const status = statuses[calls.length - 1]
      if (status) throw Object.assign(new Error(`HTTP ${status}`), { status })
      return { answers: {} }
    },
  })

  it('retries a rejected request once with a smaller body', async () => {
    const calls: Request[] = []
    await judgeSkill(failing([422], calls), brief({ body: 'word '.repeat(2000), facts: Array.from({ length: 8 }, (_, i) => fact(i + 1)) }), THRESHOLDS)
    expect(calls.length).toBe(2)
    expect(JSON.stringify(calls[1].state).length).toBeLessThan(JSON.stringify(calls[0].state).length * 0.6)
    expect(Object.keys(calls[1].questions).filter((q) => q.startsWith('unneeded_')).length).toBe(4)
  })

  it('expects answers only to the questions of the shortened request, and says it was shortened', async () => {
    const calls: Request[] = []
    const judge: Judge = {
      systemOne: async (request) => {
        calls.push(request)
        if (calls.length === 1) throw Object.assign(new Error('HTTP 413'), { status: 413 })
        return { answers: Object.fromEntries(Object.keys(request.questions).map((q) => [q, { noul: 0.1 }])) }
      },
    }
    const verdict = await judgeSkill(judge, brief({ facts: Array.from({ length: 8 }, (_, i) => fact(i + 1)) }), THRESHOLDS)
    expect(verdict.shortened).toBe(true)
    expect(verdict.unanswered).toEqual([])
    expect(Object.keys(calls[1].questions).filter((q) => q.startsWith('unneeded_')).length).toBe(4)
  })

  it('gives up after the smaller retry fails too', async () => {
    const calls: Request[] = []
    await expect(judgeSkill(failing([400, 400], calls), brief(), THRESHOLDS)).rejects.toThrow('HTTP 400')
    expect(calls.length).toBe(2)
  })

  it('does not retry an authentication, rate-limit or server failure', async () => {
    for (const status of [401, 403, 429, 500]) {
      const calls: Request[] = []
      await expect(judgeSkill(failing([status], calls), brief(), THRESHOLDS)).rejects.toThrow(`HTTP ${status}`)
      expect(calls.length).toBe(1)
    }
  })
})
