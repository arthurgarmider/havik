import { classifyPath, type SensitivityMap } from './sensitivity'
import { redactSecrets } from './redact'
import { CURL_NO_VALUE, joinLines, segments, uploadsData, windows } from './shell-patterns'

// Line-level evidence of "reads a secret" and "sends data out". Used for shell, Python and any file
// the AST analyzer cannot parse; it is deliberately simple and judged by the fixtures, not by theory.
export interface Source { readonly line: number; readonly strong: boolean; readonly snippet: string }
export interface Sink { readonly line: number; readonly snippet: string; readonly host?: string }
export interface LineScan { readonly sources: Source[]; readonly sinks: Sink[] }

const READ_CALL = /\b(?:readFileSync|readFile|createReadStream|open|read_text|read_bytes|readlines?)\s*\(|\b(?:cat|cp|tar|zip|scp|rsync|base64)\s|@["']?(?:~|\$HOME|\/|\.)|--upload-file/
const QUOTED = /'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|`((?:\\.|[^`\\])*)`/g
const WHOLE_ENV = /\bprocess\.env\b(?!\s*[.[])|\bprocess\[\s*['"]env['"]\s*\]|\bos\.environ\b(?!\s*(?:\.get\b|\[))|\bprintenv\b|\benv\s*\|/
// Only an environment that is serialised or enumerated is a source; passing it to a child process or a function is routine.
const ENV_SERIALISED = /JSON\.stringify|Object\.(?:entries|keys|values)|\bBuffer\.from|\bbtoa\s*\(|json\.dumps|urlencode|\bdict\s*\(\s*os\.environ|\bstr\s*\(\s*os\.environ|\bprintenv\b|\benv\s*\|/
const ALWAYS_SENDS = /\b(?:axios|requests|httpx|got)\.(?:post|put|patch)\s*\(/
const SENDS_WHEN_BODY = /\bfetch\s*\(|\bhttps?\.request\s*\(|\burlopen\s*\(|\baxios\.request\s*\(/
const HAS_BODY = /\bmethod\s*:\s*['"`](?:POST|PUT|PATCH)['"`]|\bbody\s*:|\bdata\s*=|\bjson\s*=/i
// The schemes curl speaks, and WebSocket. Only http and https may have one slash, as curl and the WHATWG parser allow; ssh:/x and ws:/x are paths.
const OTHER_SCHEMES = 'ftps?|sftp|scp|smbs?|tftp|gophers?|ldaps?|dict|telnet|imaps?|pop3s?|smtps?|rtsps?|rtmps?|mqtts?|ipfs|ipns|wss?'
export const URL_PREFIX = String.raw`(?<![\w./~$-])(?:https?:[/\\]+|(?:${OTHER_SCHEMES}):[/\\]{2,})`
const HOST = String.raw`(\[[^\]]+\]|[^/?#:@\s'"\`()$;|&<>,\\]+)`
// Userinfo (user:token@) is skipped: it is a credential, never the host. It ends at the last @.
// Readers split on a backslash: the WHATWG parser ends the authority there, curl and wget read on to the @.
const URL_HOST = new RegExp(String.raw`${URL_PREFIX}(?:[^/\\?#\s'"\`]*@)?${HOST}`, 'i')
// Anchored where URL_HOST found the URL, so text full of schemes cannot make it rescan.
const URL_HOST_PAST_BACKSLASH = new RegExp(String.raw`^${URL_PREFIX}(?:[^/?#\s'"\`]*@)?${HOST}`, 'i')
const LOCAL_HOST = /^(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[::1\]|[^.]+\.local)$/i
const LOOKAHEAD = 5
const CONTINUED_LINES = 20
// curl -T names a file it reads, as --upload-file does.
const CURL_UPLOADS_FILE = new RegExp(String.raw`\bcurl\b[^\n|;&]*\s-${CURL_NO_VALUE}*T`)

export const isLocalHost = (host: string | undefined): boolean => !!host && LOCAL_HOST.test(host)
// Every host a reader may connect to: when they disagree, each one that leaves the machine.
export const hostsOf = (text: string): string[] => {
  const m = URL_HOST.exec(text)
  if (!m) return []
  const readings = [...new Set([m[1], URL_HOST_PAST_BACKSLASH.exec(text.slice(m.index))?.[1] ?? m[1]])]
  const outside = readings.filter(host => !isLocalHost(host))
  return outside.length > 0 ? outside : readings.slice(-1)
}
export const hostOf = (text: string): string | undefined => hostsOf(text)[0]

// process.env is handled as whole-environment use; as a "path" it would match every env read.
export const withoutProcessEnv = (map: SensitivityMap): SensitivityMap => ({ ...map, critical: map.critical.filter(e => e.pattern !== 'process.env') })

// Path pieces are often joined at runtime (join(homedir(), '.ssh', 'id_rsa')), so classify the
// raw line and the quoted pieces glued together as a path.
const pathText = (line: string): string => `${line}\n/${[...line.matchAll(QUOTED)].map(m => m[1] ?? m[2] ?? m[3]).join('/')}`

// The simple command that crosses a line ending in a backslash, reported on the line it starts. Commands on either side of it are not part of it.
const crossingCommand = (lines: readonly string[], line: string, i: number): string | undefined => {
  const continues = (l: string): boolean => /\\\r?$/.test(l)
  if (!continues(line)) return undefined
  const joined = joinLines(`${line}\n`)
  const head = segments(joined).at(-1) ?? ''
  if (joined.endsWith('\n') || !head.trim()) return undefined
  const next = lines.slice(i + 1, i + CONTINUED_LINES + 1).map(l => l.slice(0, 4000))
  const end = next.findIndex(l => !continues(l))
  return head + (segments(joinLines((end < 0 ? next : next.slice(0, end + 1)).join('\n')))[0] ?? '')
}

export const scanLines = (lines: readonly string[], map: SensitivityMap): LineScan => {
  const pathMap = withoutProcessEnv(map)
  const sources: Source[] = []
  const sinks: Sink[] = []

  lines.forEach((full, i) => {
    for (const line of windows(full)) {
      const snippet = redactSecrets(line.trim()).slice(0, 200)
      const crossing = crossingCommand(lines, line, i)
      const text = crossing === undefined ? line : `${line}\n${crossing}`

      if (WHOLE_ENV.test(line) && ENV_SERIALISED.test(line)) {
        sources.push({ line: i + 1, strong: true, snippet })
      } else if (READ_CALL.test(text) || CURL_UPLOADS_FILE.test(text)) {
        const { level } = classifyPath(pathText(text), pathMap)
        if (level === 'critical' || level === 'high') sources.push({ line: i + 1, strong: level === 'critical', snippet })
      }

      const ahead = [line, ...lines.slice(i + 1, i + LOOKAHEAD + 1).map(l => l.slice(0, 4000))].join('\n')
      const sends = ALWAYS_SENDS.test(line) || (SENDS_WHEN_BODY.test(line) && HAS_BODY.test(ahead)) || uploadsData(line) || uploadsData(crossing ?? '')
      if (!sends) continue
      // The command's own lines first: a long one can hold its URL past the lookahead.
      const host = hostOf(crossing === undefined ? ahead : `${crossing}\n${ahead}`)
      if (!isLocalHost(host)) sinks.push({ line: i + 1, snippet, host })
    }
  })

  return { sources, sinks }
}
