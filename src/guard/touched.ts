import { basename } from 'node:path'
import { tildify } from './accesses'
import type { ReplayResult } from './replay'
import type { AuditLine } from './types'

// The one screen `npx havik` prints: what Claude Code touched lately, read from the transcripts on this machine.
const SHOWN = 3
const WIDTH = 29
const MAX_LINE = 100

// Cuts the middle part so that head + middle + tail fits on one line.
const fit = (head: string, middle: string, tail = ''): string => {
  const room = MAX_LINE - head.length - tail.length
  return `${head}${middle.length > room ? `${middle.slice(0, room - 1)}…` : middle}${tail}`
}

const distinct = (values: readonly (string | undefined)[]): string[] => [...new Set(values.filter((v): v is string => !!v))]

const row = (title: string, items: readonly string[]): string[] => {
  if (items.length === 0) return []
  const more = items.length > SHOWN ? ` (+${items.length - SHOWN})` : ''
  return [fit(`  ${title.padEnd(WIDTH)}${String(items.length).padStart(3)}  `, items.slice(0, SHOWN).join(', '), more)]
}

const of = (findings: readonly AuditLine[], detector: string): AuditLine[] => findings.filter(f => f.detector === detector)

const story = (f: AuditLine): string => fit(`  ${f.ts.slice(0, 10)}  `, f.reason ?? f.label ?? '', `  in ${basename(f.cwd ?? '')}`)

export const formatTouched = (r: ReplayResult, span: string, home: string, dir = `${home}/.claude/projects`): string => {
  if (r.toolCalls === 0) return `No Claude Code sessions in the last ${span} under ${tildify(dir, home)}.`
  const f = r.findings
  const rows = [
    ...row('sensitive files touched', distinct(of(f, 'sensitive-access').map(x => x.path && tildify(x.path, home)))),
    ...row('secrets entered the context', distinct(of(f, 'secret-in-result').flatMap(x => (x.kind ?? '').split(', ')))),
    ...row('sent out right after', distinct(of(f, 'data-leaving').map(x => x.label))),
    ...row('risky scripts', distinct(of(f, 'script-about-to-run').map(x => x.reason?.replace(/ \(line \d+\)$/, '')))),
  ]
  const critical = f.filter(x => x.severity === 'critical').slice(-SHOWN).map(story)
  const alerts = f.filter(x => x.alerted).length
  const calls = r.toolCalls.toLocaleString('en-US')
  return [
    `havik: what Claude Code touched in the last ${span}`,
    `${r.sessions} sessions · ${calls} tool calls · ${r.days} active days · read on this machine, nothing sent`,
    '',
    ...(rows.length > 0 ? rows : [`Nothing sensitive: no credential file, secret or send-after-read in ${calls} tool calls.`]),
    ...(critical.length > 0 ? ['', ...critical] : []),
    '',
    ...(alerts > 0 ? [`${alerts} warnings in ${r.days} days (${(alerts / Math.max(r.days, 1)).toFixed(1)} a day) would have reached the session.`] : []),
    'Live warnings, detect-only:  npx agent-havik guard install',
    'Every session in detail:     npx agent-havik guard replay',
  ].join('\n')
}
