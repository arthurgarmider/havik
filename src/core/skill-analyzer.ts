import { basename, join, relative } from 'node:path'
import { trace } from './trace'
import { CODE_GLOB, capabilitiesOf } from './capability-detector'
import { analyzeJsFile, isJsFile, type Obfuscation } from './js-analyzer'
import { VENDORED, fileExists, findFiles, isSymlink, readTextHead } from './fs'
import { scanLines, type Sink, type Source } from './exfil-patterns'
import { windows } from './shell-patterns'
import { loadSensitivityMap, type SensitivityMap } from './sensitivity'
import { redactSecrets } from './redact'
import type { Capability, CapabilityResult, Finding, Result, Rule, Severity } from './types'

// A skill is a directory with a SKILL.md and optional scripts. `declared` exists only when the
// framework has a permission manifest (OpenClaw); without one nothing can be "undeclared".
export interface SkillTarget {
  readonly name: string
  readonly dir: string
  readonly declared?: ReadonlySet<Capability>
}

// Bigger files are read only up to this size; the skipped rest is reported, never silently ignored.
const MAX_TEXT_BYTES = 2_000_000

let counter = 0
const nextId = (prefix: string) => `${prefix}-${String(++counter).padStart(3, '0')}`

const mismatchFindings = (skill: SkillTarget, caps: CapabilityResult, proofFile: string): Finding[] => {
  if (!skill.declared || caps.undeclared.size === 0) return []
  const { observed, undeclared } = caps
  return [{
    id: nextId('SK'),
    ruleId: 'undeclared-capability-mismatch',
    severity: 'high',
    confidence: 'high',
    owasp: 'ASI02',
    description: `Skill "${skill.name}" uses undeclared capabilities: ${[...undeclared].join(', ')}`,
    capabilities: caps,
    proof: {
      file: proofFile,
      line: 1,
      snippet: `Observed: [${[...observed].join(', ')}] | Declared: [${[...skill.declared].join(', ')}]`,
      safeToDisplay: true,
    },
  }]
}

const ruleFindings = (rules: readonly Rule[], texts: ReadonlyMap<string, string[]>): Finding[] =>
  rules
    .filter(r => r.type === 'pattern' && typeof r.match['file_contains'] === 'string')
    .flatMap(rule => {
      const pattern = new RegExp(rule.match['file_contains'] as string, 'i')
      const proseOnly = rule.match['in'] === 'skill_md'
      return [...texts].filter(([file]) => !proseOnly || basename(file) === 'SKILL.md').flatMap(([file, lines]): Finding[] => {
        const i = lines.findIndex(l => windows(l).some(w => pattern.test(w)))
        if (i < 0) return []
        return [{
          id: nextId('RU'),
          ruleId: rule.id,
          severity: rule.severity,
          confidence: rule.confidence,
          owasp: rule.owasp,
          description: rule.description,
          proof: { file, line: i + 1, snippet: redactSecrets(lines[i].trim()), safeToDisplay: true },
        }]
      })
    })

export interface FileEvidence {
  readonly file: string
  readonly sources: Source[]
  readonly sinks: Sink[]
  readonly obfuscated: readonly Obfuscation[]
  readonly skipped?: 'syntax' | 'size'
}

// JS/TS is read by the AST analyzer; shell, Python and any file it cannot parse fall back to line patterns.
export const evidenceFor = (file: string, text: string, truncated: boolean, map: SensitivityMap): FileEvidence => {
  const lines = text.split('\n')
  const lineEvidence = { file, ...scanLines(lines, map), obfuscated: [] as Obfuscation[] }
  if (truncated) return { ...lineEvidence, skipped: 'size' }
  if (!isJsFile(file)) return lineEvidence
  const js = analyzeJsFile(text, file, map)
  if (js.parsed) return { file, sources: [...js.sources], sinks: [...js.sinks], obfuscated: js.obfuscated }
  return { ...lineEvidence, skipped: text.length > 1_000_000 ? 'size' : 'syntax' }
}

// Shell and code shown in a SKILL.md (fenced blocks and `inline` spans) is read like a script; prose is not.
// Prose lines come back empty so line numbers still match the file.
const markdownCode = (lines: readonly string[]): string[] => {
  let fenced = false
  return lines.map(line => {
    if (/^\s*(?:```|~~~)/.test(line)) {
      fenced = !fenced
      return ''
    }
    return fenced ? line : [...line.matchAll(/`([^`]+)`/g)].map(m => m[1]).join(' ')
  })
}

// Scripts without an extension (scripts/steal, bin/run) are code when they start with a shebang.
const shebangScripts = async (dir: string, known: readonly string[]): Promise<string[]> => {
  const have = new Set(known)
  const found: string[] = []
  for (const file of await findFiles('{scripts,bin}/**', dir, { absolute: true, ignore: VENDORED })) {
    if (!have.has(file) && (await readTextHead(file, 2)).text === '#!') found.push(file)
  }
  return found
}

type Located<T> = T & { readonly file: string }

const exfilFindings = (skill: SkillTarget, scanned: readonly FileEvidence[]): Finding[] => {
  const declaredBoth = !!skill.declared?.has('network') && !!skill.declared?.has('credentials')
  const strongest = (sources: Array<Located<Source>>) => sources.find(s => s.strong) ?? sources[0]

  const make = (source: Located<Source>, sink: Located<Sink>, sameFile: boolean): Finding => {
    const loud = sameFile && !declaredBoth
    const severity: Severity = source.strong ? (loud ? 'critical' : 'high') : (loud ? 'high' : 'medium')
    return {
      id: nextId('XF'),
      ruleId: 'credential-exfiltration',
      severity,
      confidence: 'medium',
      owasp: 'ASI03',
      description: `Skill "${skill.name}" reads ${source.strong ? 'credentials or secrets' : 'sensitive files'} (${basename(source.file)}:${source.line}) and sends data to ${sink.host ?? 'an external host'}`,
      proof: { file: sink.file, line: sink.line, snippet: sink.snippet, safeToDisplay: true },
    }
  }

  const sameFile = scanned
    .filter(f => f.sources.length > 0 && f.sinks.length > 0)
    .map(f => make({ ...strongest(f.sources.map(s => ({ ...s, file: f.file }))) }, { ...f.sinks[0], file: f.file }, true))
  if (sameFile.length > 0) return sameFile

  // Across files only a strong source counts: a config read in one file and any POST in another is too common to report.
  const sources = scanned.flatMap(f => f.sources.filter(s => s.strong).map(s => ({ ...s, file: f.file })))
  const sinks = scanned.flatMap(f => f.sinks.map(s => ({ ...s, file: f.file })))
  return sources.length > 0 && sinks.length > 0 ? [make(strongest(sources), sinks[0], false)] : []
}

const analysisFindings = (skill: SkillTarget, scanned: readonly FileEvidence[], texts: ReadonlyMap<string, string[]>): Finding[] =>
  scanned.flatMap(f => [
    ...f.obfuscated.map((o): Finding => ({
      id: nextId('OB'),
      ruleId: 'obfuscated-sink',
      severity: 'high',
      confidence: 'high',
      owasp: 'ASI04',
      description: `Skill "${skill.name}" builds the name of a sensitive API at runtime (${o.name})`,
      proof: { file: f.file, line: o.line, snippet: redactSecrets((texts.get(f.file)?.[o.line - 1] ?? '').trim()).slice(0, 200), safeToDisplay: true },
    })),
    ...(f.skipped ? [{
      id: nextId('PF'),
      ruleId: 'parse-failed',
      severity: 'low' as const,
      confidence: 'high' as const,
      owasp: 'ASI04',
      description: f.skipped === 'size'
        ? `${relative(skill.dir, f.file)} is too large to read in full; only the first ${MAX_TEXT_BYTES / 1_000_000} MB was checked, with line patterns`
        : `Could not parse ${relative(skill.dir, f.file)}; it was checked with line patterns only`,
      proof: { file: f.file, line: 1, snippet: (texts.get(f.file)?.[0] ?? '').trim().slice(0, 200), safeToDisplay: true },
    }] : []),
  ])

// Everything the static scan learns about one skill, before it is turned into findings.
export interface Inspected {
  readonly skillMd: string | undefined
  readonly symlinked: readonly string[]
  readonly codeFiles: readonly string[]
  readonly texts: ReadonlyMap<string, string[]>
  readonly scanned: readonly FileEvidence[]
  readonly caps: CapabilityResult
}

export const inspectSkill = async (skill: SkillTarget): Promise<Inspected> => {
  const codeFiles = await findFiles(CODE_GLOB, skill.dir, { absolute: true, ignore: VENDORED })
  const sourceFiles = [...codeFiles, ...await shebangScripts(skill.dir, codeFiles)]
  const skillMd = join(skill.dir, 'SKILL.md')
  // A SKILL.md that is a symlink could be any file on this machine, so it is neither read nor sent anywhere.
  const symlinked = (await isSymlink(skillMd)) ? [skillMd] : []
  const hasSkillMd = symlinked.length === 0 && (await fileExists(skillMd))
  const files = hasSkillMd ? [skillMd, ...sourceFiles] : sourceFiles

  const texts = new Map<string, string[]>()
  const truncated = new Set<string>()
  for (const file of files) {
    const head = await readTextHead(file, MAX_TEXT_BYTES)
    texts.set(file, head.text.split('\n'))
    if (head.truncated) truncated.add(file)
  }

  const map = await loadSensitivityMap()
  const scanned = sourceFiles.map(f => evidenceFor(f, (texts.get(f) ?? []).join('\n'), truncated.has(f), map))
  if (hasSkillMd) scanned.unshift({ file: skillMd, ...scanLines(markdownCode(texts.get(skillMd) ?? []), map), obfuscated: [] })
  const observed = new Set<Capability>(sourceFiles.flatMap(f => [...capabilitiesOf(f, (texts.get(f) ?? []).join('\n'), map)]))
  const declared: ReadonlySet<Capability> = skill.declared ?? new Set()
  const caps: CapabilityResult = { observed, declared, undeclared: new Set([...observed].filter(c => !declared.has(c))) }
  return { skillMd: hasSkillMd ? skillMd : undefined, symlinked, codeFiles, texts, scanned, caps }
}

const symlinkFindings = (skill: SkillTarget, files: readonly string[]): Finding[] =>
  files.map(file => ({
    id: nextId('SY'),
    ruleId: 'symlink-not-followed',
    severity: 'low',
    confidence: 'high',
    owasp: 'ASI04',
    description: `${relative(skill.dir, file)} of skill "${skill.name}" is a symlink; havik does not follow symlinks, so it was not read`,
    proof: { file, line: 1, snippet: 'symlink', safeToDisplay: true },
  }))

export const analyzeSkill = trace(
  'analyzeSkill',
  async (skill: SkillTarget, rules: readonly Rule[]): Promise<Result<readonly Finding[]>> => {
    try {
      const { codeFiles, symlinked, texts, scanned, caps } = await inspectSkill(skill)
      return {
        ok: true,
        value: [
          ...symlinkFindings(skill, symlinked),
          ...mismatchFindings(skill, caps, codeFiles[0] ?? join(skill.dir, 'SKILL.md')),
          ...ruleFindings(rules, texts),
          ...analysisFindings(skill, scanned, texts),
          ...exfilFindings(skill, scanned),
        ],
      }
    } catch (error) {
      return { ok: false, error: `Skill analysis failed: ${error}` }
    }
  }
)
