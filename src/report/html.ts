import { tildify } from '../guard/accesses'
import { clean } from '../guard/format'
import type { ReplayResult } from '../guard/replay'
import type { AuditLine } from '../guard/types'
import type { Overview } from '../overview'
import { detailsOf, whenOf } from '../output/overview'
import { agentById } from '../agents/registry'
import { VERSION } from '../version'

// The page a person who does not use a terminal can read, print or pass on: one file, no script, nothing loaded
// from the network (the content policy forbids it), every value from an agent's records redacted, then escaped.
export interface ReportInput { readonly overview: Overview; readonly result: ReplayResult; readonly now: number; readonly home: string; readonly span: string }

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
const esc = (text: string): string => clean(text, 2_000).replace(/[&<>"']/g, c => ESCAPES[c])
const nameOf = (id: string | undefined): string => agentById(id ?? 'claude-code')?.name ?? id ?? 'an agent'
const of = (f: readonly AuditLine[], detector: string) => f.filter(x => x.detector === detector)
const uniq = (items: readonly string[]): string[] => [...new Set(items)]

const ROWS: ReadonlyArray<{ readonly label: string; readonly detector: string; readonly item: (x: AuditLine, home: string) => string }> = [
  { label: 'Password and key files an agent opened', detector: 'sensitive-access', item: (x, home) => tildify(x.path ?? '', home) },
  { label: 'Secrets you pasted into a chat', detector: 'secret-in-prompt', item: x => x.kind ?? '' },
  { label: 'Secrets an agent pulled in', detector: 'secret-in-result', item: x => x.kind ?? '' },
  { label: 'Data sent out right after', detector: 'data-leaving', item: x => x.label ?? '' },
  { label: 'Scripts that download and run code', detector: 'script-about-to-run', item: x => (x.reason ?? '').replace(/ \(line \d+\)$/, '') },
]

const agentCard = (o: Overview, i: number, input: ReportInput): string => {
  const a = o.agents[i]
  const facts = detailsOf(a, input.result.agents).slice(1)
  return `<article class="agent"><h3>${esc(a.def.name)}</h3><p class="meta"><span class="kind">${esc(a.def.kind)}</span> · ${esc(whenOf(a, input.now))}</p>${
    facts.length ? `<ul>${facts.map(f => `<li>${esc(f)}</li>`).join('')}</ul>` : ''}</article>`
}

const unreadOf = (input: ReportInput): string[] => [...new Set([...input.overview.warnings, ...input.result.warnings])]

const touchedRows = (input: ReportInput): string => {
  const rows = ROWS.flatMap(r => {
    const items = uniq(of(input.result.findings, r.detector).map(x => `${r.item(x, input.home)} (${nameOf(x.agent)})`).filter(i => !i.startsWith(' (')))
    return items.length ? [`<tr><th scope="row">${esc(r.label)}</th><td class="n">${items.length}</td><td>${items.slice(0, 12).map(esc).join('<br>')}${items.length > 12 ? `<br>and ${items.length - 12} more` : ''}</td></tr>`] : []
  })
  if (rows.length) return `<table>${rows.join('')}</table>`
  return unreadOf(input).length ? '<p>Nothing found in what havik could read; see below for what it could not.</p>' : '<p>Nothing sensitive: no password or key file, no secret and nothing sent out after one.</p>'
}

const stories = (input: ReportInput): string => {
  const serious = input.result.findings.filter(x => x.severity === 'critical').slice(-8)
  return serious.length ? `<h3>The most serious</h3><ul class="stories">${serious.map(x => `<li><time>${esc(x.ts.slice(0, 10))}</time> ${esc(nameOf(x.agent))}: ${esc(x.reason ?? x.label ?? '')}</li>`).join('')}</ul>` : ''
}

// What to do next, only for what was found.
const advice = (input: ReportInput): string => {
  const f = input.result.findings
  const reachable = input.overview.agents.filter(a => (a.setup?.channels.length ?? 0) > 0)
  const tips = [
    ...(of(f, 'secret-in-prompt').length ? ['Change (rotate) the passwords and keys you pasted into a chat with an agent: they are kept in the agent\'s records on this computer and were sent to the company that runs the AI.'] : []),
    ...(of(f, 'secret-in-result').length || of(f, 'sensitive-access').length ? ['Look at the password and key files listed above. If an agent had no reason to open one, change the secret it holds.'] : []),
    ...(of(f, 'data-leaving').length ? ['Something was sent out right after a secret was read. Check where it went; if you do not know the address, treat the secret as exposed and change it.'] : []),
    ...reachable.map(a => `${a.def.name} acts on messages it receives from ${a.setup?.channels.join(', ')}. Make sure only you can write to it there.`),
    'To be warned while agents work, run: npx agent-havik guard install --agent all. It records and warns, and never blocks anything.',
  ]
  return `<ul>${tips.map(t => `<li>${esc(t)}</li>`).join('')}</ul>`
}

const WORDS: ReadonlyArray<readonly [string, string]> = [
  ['AI agent', 'a program that uses an AI model to act on your computer: run commands, read and change files, open web pages.'],
  ['Tool server', 'an add-on that gives an agent more abilities, such as reading your email or a company system.'],
  ['Secret', 'a password, key or token that opens an account or a service.'],
  ['Sent out right after', 'the agent sent data to the internet soon after a secret was read: the pattern of a leak, though not proof of one.'],
  ['Self-running agent', 'an agent that starts work on its own schedule or when a message arrives, without you at the keyboard.'],
]

const CSS = `
:root{--bg:#fbfaf7;--fg:#1f2328;--muted:#5d6670;--line:#e3e0d8;--card:#fff;--accent:#8a3b12}
@media (prefers-color-scheme:dark){:root{--bg:#16181b;--fg:#e8e6e3;--muted:#a0a7ae;--line:#30343a;--card:#1d2024;--accent:#f0a46b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:40px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:17px;margin:0 0 4px}.sub,.meta,footer{color:var(--muted)}.kind{color:var(--accent)}
.agents{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}.agent{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.agent ul{margin:8px 0 0;padding-left:18px}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid var(--line)}
td.n{width:3em;font-variant-numeric:tabular-nums}.stories time{color:var(--muted);font-variant-numeric:tabular-nums;margin-right:6px}dt{font-weight:600}dd{margin:0 0 10px}
@media print{body{background:#fff;color:#000}}`

export const renderReport = (input: ReportInput): string => {
  const { overview: o, result: r } = input
  const conversations = Object.values(r.agents).reduce((n, a) => n + a.sessions, 0)
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>AI agents on this computer</title><style>${CSS}</style></head>
<body><main>
<header><h1>The AI agents on this computer</h1><p class="sub">Made by havik on ${esc(new Date(input.now).toISOString().slice(0, 10))}, by looking at this computer only. Nothing in this page left it.</p></header>
<h2>Agents found</h2>
${o.agents.length ? `<div class="agents">${o.agents.map((_, i) => agentCard(o, i, input)).join('\n')}</div>` : '<p>No AI agents found on this computer.</p>'}
${o.processesChecked ? '' : '<p class="sub">havik could not see which programs are running, so none is shown as running now.</p>'}
<h2>What they did in the last ${esc(input.span)}</h2>
<p class="sub">From their own records: ${conversations.toLocaleString('en-US')} conversations, ${r.toolCalls.toLocaleString('en-US')} actions on ${r.days} days.</p>
${touchedRows(input)}
${stories(input)}
${unreadOf(input).length ? `<h3>Could not read</h3><ul>${unreadOf(input).map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
<h2>What you can do</h2>
${advice(input)}
<h2>Words used here</h2>
<dl>${WORDS.map(([w, d]) => `<dt>${esc(w)}</dt><dd>${esc(d)}</dd>`).join('')}</dl>
<footer><p>havik ${esc(VERSION)} · made again with <code>npx agent-havik report</code></p></footer>
</main></body></html>
`
}
