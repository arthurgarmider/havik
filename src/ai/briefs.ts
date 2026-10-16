import { splitFrontmatter } from '../core/frontmatter'
import { trace } from '../core/trace'
import { inspectSkill, type SkillTarget } from '../core/skill-analyzer'
import type { Fact, SkillBrief } from './jev'

// A skill as Jev sees it: what SKILL.md says, and what the static scan found the code doing.
// A send counts as strong only when the skill also reads something sensitive.
export const briefFor = trace('briefFor', async (skill: SkillTarget): Promise<SkillBrief | null> => {
  const { skillMd, texts, scanned } = await inspectSkill(skill)
  if (!skillMd) return null
  const text = (texts.get(skillMd) ?? []).join('\n')
  let parsed: { data: Record<string, unknown>; body: string }
  try {
    parsed = splitFrontmatter(text)
  } catch {
    parsed = { data: {}, body: text.replace(/^---\n[\s\S]*?\n---\n?/, '') }
  }
  const description = typeof parsed.data['description'] === 'string' ? parsed.data['description'] : ''
  if (!description && !parsed.body.trim()) return null

  const reads = scanned.some(f => f.sources.some(s => s.strong))
  const facts: Fact[] = scanned.flatMap(f => [
    ...f.sources.map(s => ({ text: `reads ${s.strong ? 'credentials or secrets' : 'sensitive files'}: ${s.snippet}`, file: f.file, line: s.line, strong: s.strong })),
    ...f.sinks.map(s => ({ text: `sends data to ${s.host ?? 'an external host'}: ${s.snippet}`, file: f.file, line: s.line, strong: reads })),
    ...f.obfuscated.map(o => ({ text: `builds the name "${o.name}" at runtime`, file: f.file, line: o.line, strong: false })),
  ])
  facts.sort((a, b) => Number(b.strong) - Number(a.strong))
  return { name: skill.name, dir: skill.dir, file: skillMd, description, body: parsed.body, facts }
})
