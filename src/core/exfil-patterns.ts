import { classifyPath, type SensitivityMap } from './sensitivity'
import { redactSecrets } from './redact'
import { uploadsData, windows } from './shell-patterns'

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
// Userinfo (user:token@) is skipped: it is a credential, never the host.
const URL_HOST = /https?:\/\/(?:[^/?#@\s'"`]*@)?(\[[^\]]+\]|[^/:@\s'"`()$;|&<>,\\]+)/
const LOCAL_HOST = /^(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[::1\]|[^.]+\.local)$/i
const LOOKAHEAD = 5

export const hostOf = (text: string): string | undefined => URL_HOST.exec(text)?.[1]
export const isLocalHost = (host: string | undefined): boolean => !!host && LOCAL_HOST.test(host)

// process.env is handled as whole-environment use; as a "path" it would match every env read.
export const withoutProcessEnv = (map: SensitivityMap): SensitivityMap => ({ ...map, critical: map.critical.filter(e => e.pattern !== 'process.env') })

// Path pieces are often joined at runtime (join(homedir(), '.ssh', 'id_rsa')), so classify the
// raw line and the quoted pieces glued together as a path.
const pathText = (line: string): string => `${line}\n/${[...line.matchAll(QUOTED)].map(m => m[1] ?? m[2] ?? m[3]).join('/')}`

export const scanLines = (lines: readonly string[], map: SensitivityMap): LineScan => {
  const pathMap = withoutProcessEnv(map)
  const sources: Source[] = []
  const sinks: Sink[] = []

  lines.forEach((full, i) => {
    for (const line of windows(full)) {
      const snippet = redactSecrets(line.trim()).slice(0, 200)

      if (WHOLE_ENV.test(line) && ENV_SERIALISED.test(line)) {
        sources.push({ line: i + 1, strong: true, snippet })
      } else if (READ_CALL.test(line)) {
        const { level } = classifyPath(pathText(line), pathMap)
        if (level === 'critical' || level === 'high') sources.push({ line: i + 1, strong: level === 'critical', snippet })
      }

      const ahead = [line, ...lines.slice(i + 1, i + LOOKAHEAD + 1).map(l => l.slice(0, 4000))].join('\n')
      const sends = ALWAYS_SENDS.test(line) || (SENDS_WHEN_BODY.test(line) && HAS_BODY.test(ahead)) || uploadsData(line)
      if (!sends) continue
      const host = hostOf(ahead)
      if (!isLocalHost(host)) sinks.push({ line: i + 1, snippet, host })
    }
  })

  return { sources, sinks }
}
