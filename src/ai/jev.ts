import { trace } from '../core/trace'
import type { Finding } from '../core/types'
import { FAMILIES, MAX, UNNEEDED, clip, questionsFor, stateFor, type Question, type SkillBrief, type State } from './questions'

export type { Fact, SkillBrief } from './questions'
export { FAMILIES } from './questions'

// The part of the TypeSafe client that havik uses, so tests can stand in for it.
export interface Judge {
  systemOne(request: { state: State; questions: Record<string, Question> }): PromiseLike<{ readonly answers: Record<string, { readonly noul: number } | undefined> }>
}
export type Thresholds = Readonly<Record<string, number | null>>
// unanswered: asked but not answered with a probability; shortened: the request had to be cut to get any answer.
export interface Verdict { readonly findings: Finding[]; readonly uncalibrated: string[]; readonly unanswered: string[]; readonly shortened: boolean }

let counter = 0
const nextId = () => `AI-${String(++counter).padStart(3, '0')}`

const confidence = (p: number, threshold: number): Finding['confidence'] => {
  const margin = (p - threshold) / (1 - threshold)
  return margin >= 0.5 ? 'high' : margin >= 0.2 ? 'medium' : 'low'
}

// A rejected request (400, 413, 422...) is retried once with half the text; authentication, rate limits and server errors are not.
const isRejection = (error: unknown): boolean => {
  const status = (error as { status?: unknown } | null)?.status
  return typeof status === 'number' && status >= 400 && status < 500 && ![401, 403, 429].includes(status)
}

// One request with every question about the skill; the raw answers are what calibration measures.
export async function askJev(judge: Judge, brief: SkillBrief) {
  const ask = async (shortened: boolean) => {
    const facts = brief.facts.slice(0, shortened ? MAX.facts / 2 : MAX.facts)
    const questions = questionsFor(facts)
    const reply = await judge.systemOne({ state: stateFor(brief, facts, shortened ? MAX.body / 2 : MAX.body), questions })
    // The reply is external data: without an answers object there is nothing to read, and that must not look like a clean result.
    if (!reply || typeof reply.answers !== 'object' || reply.answers === null) throw new Error('Jev returned no answers')
    return { answers: reply.answers, asked: Object.keys(questions), shortened }
  }
  try {
    return await ask(false)
  } catch (error) {
    if (!isRejection(error)) throw error
    return ask(true)
  }
}

export const judgeSkill = trace('judgeSkill', async (judge: Judge, brief: SkillBrief, thresholds: Thresholds): Promise<Verdict> => {
  const { answers, asked, shortened } = await askJev(judge, brief)
  const findings: Finding[] = []
  const uncalibrated = new Set<string>()
  // Only a probability from 0 to 1 counts as an answer.
  const yes = (name: string): number | undefined => {
    const p = answers[name]?.noul
    return typeof p === 'number' && p >= 0 && p <= 1 ? p : undefined
  }
  const decide = (key: string, name: string, make: (p: number, t: number) => Finding) => {
    const p = yes(name)
    const threshold = thresholds[key]
    if (p === undefined) return
    if (typeof threshold !== 'number' || !(threshold > 0 && threshold < 1)) return void uncalibrated.add(key)
    if (p >= threshold) findings.push(make(p, threshold))
  }
  const percent = (p: number, t: number) => `Jev answered yes at ${Math.round(p * 100)}%, threshold ${Math.round(t * 100)}%`
  for (const f of FAMILIES) {
    decide(f.key, f.name, (p, t) => ({
      id: nextId(), ruleId: f.ruleId, severity: f.severity, confidence: confidence(p, t), owasp: f.owasp,
      description: `Skill "${brief.name}" ${f.says} (${percent(p, t)})`,
      proof: { file: brief.file, line: 1, snippet: clip(brief.description || brief.name, MAX.line), safeToDisplay: true },
    }))
  }
  brief.facts.slice(0, MAX.facts).forEach((fact, i) => decide(UNNEEDED.key, `unneeded_${i + 1}`, (p, t) => ({
    id: nextId(), ruleId: UNNEEDED.ruleId, severity: fact.strong ? 'critical' : 'high', confidence: confidence(p, t), owasp: UNNEEDED.owasp,
    description: `Skill "${brief.name}" does something its description gives no reason for (${percent(p, t)})`,
    proof: { file: fact.file, line: fact.line, snippet: clip(fact.text, MAX.line), safeToDisplay: true },
  })))
  return { findings, uncalibrated: [...uncalibrated], unanswered: asked.filter(name => yes(name) === undefined), shortened }
})
