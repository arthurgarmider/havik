import { homedir } from 'node:os'
import { basename, resolve } from 'node:path'
import { URL_PREFIX, hostOf, hostsOf, isLocalHost } from '../core/exfil-patterns'
import { CURL_NO_VALUE, joinLines, segments, uploadsData } from '../core/shell-patterns'
import { asRecord } from '../core/json'
import type { Access } from './types'

const MAX_STRINGS = 1_000
const MAX_STRING_BYTES = 64_000

// Quoted strings and bare words; every alternative is unambiguous, so the scan is linear. A double quote that never
// closes runs to the end of the text; failing there instead, it would be retried at every later quote.
const TOKEN = /'([^']*)'|"((?:\\[\s\S]?|[^"\\])*)("|$)|([^\s'"|;&<>()]+)/g
const REDIRECT = /(?:^|[^<>&\d])>{1,2}\s*('[^']*'|"(?:\\.|[^"\\])*"|[^\s;&|<>]+)/g
const NETWORK_PROGRAMS = ['curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'rsync', 'sftp', 'ftp', 'http', 'xh']
const UPLOAD_PROGRAMS = ['ssh', 'scp', 'rsync', 'sftp', 'ftp', 'nc', 'ncat', 'netcat']
// One of these names anywhere in the text (sudo curl, | xargs curl), or after a path right at the start of a substitution. A path elsewhere is only a path: cd vendor/ssh. Other paths are found by the program's position.
const wordAmong = (names: readonly string[]): RegExp => new RegExp(`(?<!\\\\)(?:(?:^|[\\s;&|(\`])|[(\`][\\w./~-]*/)(${names.join('|')})(?=\\s)`)
const NETWORK_TOOL = wordAmong(NETWORK_PROGRAMS)
const UPLOADER = wordAmong(UPLOAD_PROGRAMS)
const URLS = new RegExp(String.raw`${URL_PREFIX}[^\s'"\`)]*`, 'gi')
const SCP_HOST = /(?:^|\s)(?:[\w.-]{1,64}@)?([\w-]{1,63}(?:\.[\w-]{1,63}){1,10}):(?!\/\/)/g
const HOST_LIKE = /^(?:[\w-]{1,63}\.)+[a-z][\w-]{0,62}$|^\d{1,3}(?:\.\d{1,3}){3}$/i
const RUNNER = /^(?:node|bun|deno|python[23]?|ruby|perl|php|sh|bash|zsh)$/
const INLINE_FLAG = /^-(?:c|e|p|-eval|-print)$/
// Words before the program: assignments, shell keywords, and wrappers, whose own flags and numbers come next.
const WRAPPER = /^(?:sudo|exec|time|nohup|env|command|timeout|nice|ionice|stdbuf|xargs)$/
const PREFIX = /^(?:export|local|declare|if|then|elif|else|while|until|do|!|\{)$|^\w+=/
const WRAPPER_ARGUMENT = /^-|^\d+(?:\.\d+)?[smhd]?$/
const WRAPPER_VALUE_FLAG = new Map([
  ['sudo', /^(?:-[ugCDhpRrTU]|--user|--group)$/],
  ['timeout', /^-[ks]$/],
  ['nice', /^-n$/],
  ['ionice', /^-[cnp]$/],
  ['stdbuf', /^-[ioe]$/],
  ['xargs', /^-[IJLnPdEs]$/],
  ['env', /^-[uCS]$/],
  ['time', /^-[fo]$/],
])
// Programs that name a path without reading its contents: a `cd` or `ls` of a credential directory is not a read.
const NON_READERS = new Set(['cd', 'ls', 'mkdir', 'rmdir', 'touch', 'stat', 'test', '[', '[[', 'echo', 'printf', 'pwd', 'which', 'du', 'df', 'find', 'tree', 'file', 'basename', 'dirname', 'realpath', 'readlink', 'chmod', 'chown', 'rm', 'ln', 'git', 'pushd', 'popd', 'open', 'code', 'xdg-open'])
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|pl|php|sh|bash|zsh|fish)$/i
const HEREDOC = /(?<!<)<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1/
// A GET of a plain page cannot carry much; a query string or a long opaque path segment can.
const LONG_RUN = /[A-Za-z0-9+/=_-]{32,}/g
// Article and document names run long too: words joined by hyphens, not encoded data.
// shortcut: data split into pieces that mostly read as words passes (the README says so); tighten if a real case appears.
const WORD = /^(?:[A-Za-z][a-z]{0,23}|[A-Z]{1,24}|\d{1,20}|[A-Za-z0-9]{1,4})$/
// Most pieces must read as words, so base64's four-letter units and hex or decimal bytes joined by hyphens do not pass.
const NAMED_WORD = /^[A-Za-z][a-z]{2,23}$/
const isWords = (run: string): boolean => {
  const words = run.split(/[-_]+/).filter(Boolean)
  const named = words.filter(w => NAMED_WORD.test(w)).length
  return words.length >= 3 && words.every(w => WORD.test(w)) && named * 2 >= words.length
}
const hasEncodedRun = (text: string): boolean => (text.match(LONG_RUN) ?? []).some(run => !isWords(run))
// Past this length a URL can hold anything, whatever its shape.
const URL_MAX_CHARS = 512
export const urlCarriesData = (url: string): boolean => {
  if (url.length > URL_MAX_CHARS) return true
  const start = /^[a-z][a-z0-9+.-]*:[/\\]+([^/?#]*)/i.exec(url)
  const authority = start?.[1] ?? ''
  const [path, ...after] = url.slice(start?.[0].length ?? 0).split(/[?#]/)
  return authority.includes('@') || hasEncodedRun(authority) || after.join('').length > 0 || path.split('/').some(hasEncodedRun)
}
const HOME_FORM = /^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/
const CHANNEL_HOSTS: Record<string, string> = { telegram: 'api.telegram.org', slack: 'slack.com', discord: 'discord.com', whatsapp: 'web.whatsapp.com', signal: 'signal.org', matrix: 'matrix.org' }
const PATCH_FILE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm
// ssh and its relatives use a key to authenticate; the key's contents never reach the output.
const KEY_USERS = new Set(['ssh', 'scp', 'sftp', 'rsync', 'ssh-add'])
const IDENTITY_OPTION = /^(?:-o)?IdentityFile=/i
// A command substitution inside double quotes runs like any other command.
const DOUBLE_QUOTED = /"((?:\\[\s\S]?|[^"\\])*)(?:"|$)/g
const SUBSTITUTION = /(?<!\\)\$\(([^()]*)\)|(?<!\\)`([^`]*?)(?<!\\)`/g
const EXEC_FLAG = /^-(?:exec|execdir|ok|okdir)$/
const XARGS = /(?:^|[\s|])xargs\s/

// No later quote can close either, since each was escaped in that scan, so the rest is read as bare words, once.
const tokens = (text: string): string[] => [...text.matchAll(TOKEN)].flatMap(m => (m[3] === '' ? tokens(m[2].replace(/"/g, ' ')) : [m[1] ?? m[2] ?? m[4] ?? '']))

export const tildify = (path: string, home = homedir()): string => (path === home || path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path)

// A token that names a file: absolute, home-relative or explicitly relative. Bare words are not paths.
export const expandPath = (raw: string, cwd: string, home = homedir()): string | undefined => {
  // --data=@f, file=@f and field=<f all name the file after the = sign.
  const t = raw.replace(/^(?:(?:--?)?[\w.-]+=)+/, '').replace(/^[@<]/, '')
  if (HOME_FORM.test(t)) return resolve(home, t.replace(HOME_FORM, '.'))
  if (t.startsWith('/')) return resolve(t)
  if (t.startsWith('./') || t.startsWith('../')) return resolve(cwd, t)
  return undefined
}

// Every string inside a value, depth-first, within a count and size budget. Iterative, so depth cannot overflow.
export const stringsOf = (value: unknown, maxStrings = MAX_STRINGS, maxBytes = MAX_STRING_BYTES): string[] => {
  const out: string[] = []
  let bytes = 0
  const stack: unknown[] = [value]
  while (stack.length > 0 && out.length < maxStrings && bytes < maxBytes) {
    const v = stack.pop()
    if (typeof v === 'string') {
      out.push(v.slice(0, maxBytes - bytes))
      bytes += v.length
    } else if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push(v[i])
    } else if (v && typeof v === 'object') {
      const vals = Object.values(v)
      for (let i = vals.length - 1; i >= 0; i--) stack.push(vals[i])
    }
  }
  return out
}

const program = (words: readonly string[]): { name: string; rest: string[] } => {
  let wrapped = false
  let valueFlag: RegExp | undefined
  let i = 0
  for (; i < words.length; i++) {
    const w = words[i]
    if (WRAPPER.test(w)) {
      wrapped = true
      valueFlag = WRAPPER_VALUE_FLAG.get(w)
    } else if (wrapped && WRAPPER_ARGUMENT.test(w)) {
      if (valueFlag?.test(w)) i++
    } else if (!PREFIX.test(w)) {
      break
    }
  }
  return i < words.length ? { name: words[i], rest: words.slice(i + 1) } : { name: '', rest: [] }
}

// The name as the program knows itself: /usr/bin/curl, \\curl and, on a case-insensitive filesystem, CURL all run curl.
const programName = (name: string): string => {
  const base = basename(name.replace(/^\\/, ''))
  return NETWORK_PROGRAMS.includes(base.toLowerCase()) ? base.toLowerCase() : base
}

interface Parsed { readonly segment: string; readonly words: string[] }

// curl and wget take a URL with no scheme, in a word that is neither a file name, a redirect's target, nor the value of a flag.
const BARE_URL = /^(?:[^\s/@]{1,200}@)?(?:(?:[\w-]{1,63}\.)+[a-z][\w-]{1,62}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:[/?#][\s\S]*)?$/i
// shortcut: a bare name such as evil.sh, with no path or port, reads as a file (the README says so); a host list would need upkeep.
const FILE_NAME = /^[^/?#:]+\.(?:txt|jsonl?|ya?ml|xml|html?|csv|tsv|log|md|rst|data?|pem|crt|cer|der|key|p12|pfx|jks|conf|cfg|ini|toml|env|lock|sock|gz|tgz|bz2|xz|zip|tar|7z|deb|rpm|apk|dmg|msi|exe|iso|whl|jar|so|bin|out|tmp|bak|sh|py|js|ts|rb|go|rs|java|png|jpe?g|gif|svg|pdf|mp4|wav)$/i
const REDIRECTION = /\d*(?:&>>?|[<>]{1,2}&?)\s*(?:'[^']*'|"[^"]*"|[^\s;&|<>]+)/g
// The word after a long flag is taken for its value unless the flag is known to take none: a password given with an unlisted flag must never be recorded as a host.
// shortcut: a URL with no scheme right after an uncommon flag that takes no value is missed (the README says so); a full table would need upkeep with every curl release.
const VALUE_FLAG = new Map([
  ['curl', new RegExp(`^-${CURL_NO_VALUE}*[ACDEFHKPQTUXYbcdehmortuwyz]$|^--(?!(?:silent|show-error|location|location-trusted|fail|fail-with-body|fail-early|insecure|compressed|verbose|include|head|get|globoff|ipv4|ipv6|http1\\.0|http1\\.1|http2|http2-prior-knowledge|http3|no-buffer|no-keepalive|no-progress-meter|no-sessionid|progress-bar|remote-name|remote-name-all|remote-header-name|remote-time|create-dirs|list-only|netrc|parallel|path-as-is|raw|tcp-nodelay|tr-encoding|anyauth|basic|digest|ntlm|negotiate|ssl|ssl-reqd|tlsv1\\.2|tlsv1\\.3|junk-session-cookies)$)[\\w.-]+$`)],
  ['wget', /^-[46bcdEFhHkKLmNpqrSvVx]*[aABDeiIlOoPQRtTUwX]$|^--(?!(?:quiet|verbose|no-verbose|server-response|spider|continue|timestamping|no-check-certificate|content-disposition|recursive|no-parent|mirror|page-requisites|convert-links|no-clobber|force-directories|no-directories|inet4-only|inet6-only|debug|background|no-cookies|no-cache)$)[\w.-]+$/],
])
const bareUrls = (parsed: readonly Parsed[]): string[] => parsed.flatMap(({ segment, words }) => {
  const valueFlag = VALUE_FLAG.get(programName(program(words).name))
  if (!valueFlag) return []
  const { rest } = program(tokens(segment.replace(REDIRECTION, ' ')))
  return rest.filter((w, i) => !w.startsWith('-') && BARE_URL.test(w) && !FILE_NAME.test(w) && (rest[i - 1] === '--url' || !valueFlag.test(rest[i - 1] ?? '')))
})

const bashHosts = (command: string, parsed: readonly Parsed[], urlWords: readonly string[]): string[] => {
  const hosts = new Set(urlWords.flatMap(hostsOf))
  for (const m of command.matchAll(SCP_HOST)) hosts.add(m[1])
  for (const { words } of parsed) {
    const { name, rest } = program(words)
    if (!['ssh', 'nc', 'ncat', 'netcat', 'sftp', 'ftp'].includes(programName(name))) continue
    const host = rest.map(w => w.replace(/^[^@]*@/, '')).find(w => HOST_LIKE.test(w))
    if (host) hosts.add(host)
  }
  return [...hosts]
}

// What a download saves: curl -o f, -sSo f, -of and --output f, the headers (-D) and cookies (-c); wget -O f, -qO f, -Of, --output-document=f, its log (-o, -a) and cookies.
const OUTPUT_FLAG = new Map([
  ['curl', new RegExp(`^(?:-${CURL_NO_VALUE}*[oDc](.+)?|--(?:output|dump-header|cookie-jar))$`)],
  ['wget', /^(?:-[46bcdEFhHkKLmNpqrSvVx]*[Ooa](.+)?|--(?:output-document|output-file|append-output|save-cookies)(?:=(.+))?)$/],
])
// By position, not by name: curl -T x -o x uploads x before saving over it.
const outputArguments = (via: string, rest: readonly string[]): Array<{ at: number; target: string }> => {
  const flag = OUTPUT_FLAG.get(via)
  if (!flag) return []
  return rest.flatMap((word, i) => {
    const m = flag.exec(word)
    const joined = m?.[1] ?? m?.[2]
    return !m ? [] : joined === undefined ? [{ at: i + 1, target: rest[i + 1] ?? '' }] : [{ at: i, target: joined }]
  })
}
// curl -d@f and -sT./f join the flag and the file; --variable name@f and --data-urlencode name@f name one after the @.
const CURL_JOINED_FLAG = new RegExp(`^-${CURL_NO_VALUE}*[dFTK]`)
const curlFile = (word: string, previous: string | undefined): string =>
  (previous === '--variable' || previous === '--data-urlencode' ? word.replace(/^[^@=]*@/, '') : word.replace(CURL_JOINED_FLAG, ''))

// Write targets of one simple command: redirects, tee arguments, the last argument of cp and mv.
const writeTargets = (segment: string, via: string, rest: readonly string[]): Set<string> => {
  const targets = new Set([...segment.matchAll(REDIRECT)].map(m => tokens(m[1])[0] ?? ''))
  if (via === 'tee') rest.filter(w => !w.startsWith('-')).forEach(w => targets.add(w))
  if ((via === 'cp' || via === 'mv') && rest.length > 1) targets.add(rest[rest.length - 1])
  return targets
}

const keyArguments = (via: string, rest: readonly string[]): Set<string> =>
  new Set(KEY_USERS.has(via) ? rest.filter((w, i) => via === 'ssh-add' || rest[i - 1] === '-i' || IDENTITY_OPTION.test(w)) : [])

// `fedToReader` is set when xargs hands this command's output to another program as arguments.
const segmentAccesses = ({ segment, words }: Parsed, cwd: string, home: string, fedToReader = false): Access[] => {
  const { name, rest } = program(words)
  // A path assigned to a variable (F=~/.ssh/id_rsa) is read by whatever uses the variable next.
  const assigned = words.slice(0, words.length - rest.length).filter(w => /^\w+=./.test(w)).flatMap(w => { const p = expandPath(w.replace(/^\w+=/, ''), cwd, home); return p ? [p] : [] })
  if (!name) return assigned.map((path): Access => ({ kind: 'read', path, via: 'assignment' }))
  const via = programName(name)
  const out: Access[] = assigned.map((path): Access => ({ kind: 'read', path, via }))
  let scriptToken: string | undefined
  if (RUNNER.test(via)) {
    const inline = rest.findIndex(w => INLINE_FLAG.test(w))
    scriptToken = inline < 0 ? rest.find(w => !w.startsWith('-')) : undefined
    if (inline >= 0) out.push({ kind: 'inline-code', path: cwd, via })
    else if (scriptToken && CODE_FILE.test(scriptToken)) out.push({ kind: 'script', path: expandPath(scriptToken, cwd, home) ?? resolve(cwd, scriptToken), via })
  } else if ((name.startsWith('./') || name.startsWith('../')) && (CODE_FILE.test(name) || !/\.\w+$/.test(name))) {
    // An explicitly relative program that is code or has no extension at all is a script of this project; prose is not.
    out.push({ kind: 'script', path: expandPath(name, cwd, home) ?? resolve(cwd, name), via: name })
  } else if (!RUNNER.test(via) && !NON_READERS.has(via) && !name.startsWith('./') && !name.startsWith('../') && /\.\w+$/.test(name) && !name.includes('/')) {
    return []
  }
  const writes = writeTargets(segment, via, rest)
  const reads = !NON_READERS.has(via) || fedToReader || (via === 'find' && rest.some(w => EXEC_FLAG.test(w)))
  const keys = keyArguments(via, rest)
  const outputs = outputArguments(via, rest)
  const saved = new Set(outputs.map(o => o.at))
  for (const [i, word] of rest.entries()) {
    if (!reads || word === scriptToken || writes.has(word) || saved.has(i)) continue
    const path = expandPath(via === 'curl' ? curlFile(word, rest[i - 1]) : word, cwd, home)
    if (path) out.push({ kind: keys.has(word) ? 'use' : 'read', path, via })
  }
  for (const word of [...writes, ...outputs.map(o => o.target)]) {
    const path = expandPath(word, cwd, home)
    if (path) out.push({ kind: 'write', path, via })
  }
  return out
}

// A heredoc body is data, not commands: it is dropped, the line that opens it is kept. A << in a string or a comment opens nothing,
// so what is open is tracked from line to line: a quote, or a $( or ( inside which text is code again, even in double quotes.
const withoutHeredocs = (command: string): string => {
  const out: string[] = []
  const open: string[] = []
  // Returns whether the text ended in a comment.
  const walk = (text: string): boolean => {
    for (let i = 0; i < text.length; i++) {
      const c = text[i]
      const top = open[open.length - 1]
      if (top === "'") {
        if (c === "'") open.pop()
      } else if (c === '\\') {
        i++
      } else if (top === '"') {
        if (c === '"') open.pop()
        else if (c === '$' && text[i + 1] === '(') { open.push('('); i++ }
      } else if (c === '"' || c === "'" || c === '(') {
        open.push(c)
      } else if (c === ')' && top === '(') {
        open.pop()
      } else if (c === '#' && (i === 0 || /[\s;&|(]/.test(text[i - 1]))) {
        return true
      }
    }
    return false
  }
  let terminator: string | undefined
  for (const line of command.split('\n')) {
    if (terminator !== undefined) {
      if (line.trim() === terminator) terminator = undefined
      continue
    }
    out.push(line)
    const opener = HEREDOC.exec(line)
    const commented = walk(opener ? line.slice(0, opener.index) : line)
    const top = open[open.length - 1]
    if (opener && !commented && top !== '"' && top !== "'") terminator = opener[2]
    if (opener && !commented) walk(line.slice(opener.index))
  }
  return out.join('\n')
}

// `"$HOME"/x` is one path to the shell and two tokens to the tokenizer; glue it back together first.
const QUOTED_HOME = /["']\$\{?HOME\}?["'](?=\/)/g

// A command's output in a URL can be anything.
// shortcut: a plain variable counts only when named like a secret or like data, because $ID or $VERSION in a URL is routine; widen this if a real case appears.
const SHELL_VALUE = /\$\(|`|\$\{?\w*(?:TOKEN|KEY|SECRET|PASS(?:WORD|WD)?|AUTH|CREDS?|CREDENTIALS?|JWT|BEARER|COOKIE|_PAT|_?PW|DATA|PAYLOAD|B64|BASE64|ENCODED)(?:_\w*)?\}?(?!\w)/i
// The URL pattern stops at a quote or a backtick, but the shell joins whatever is glued on after it, and drops the quotes.
// Read through a bounded slice, or a command holding many URLs takes quadratic time; a slice it fills is past the URL limit.
const GLUED_ON = /^["']*[^\s;|&<>),}]*/
const shellWord = (command: string, m: RegExpMatchArray): string => {
  const end = (m.index ?? 0) + m[0].length
  // A backtick at the very end closes a substitution around the URL; it holds nothing.
  return (m[0] + (GLUED_ON.exec(command.slice(end, end + URL_MAX_CHARS + 1))?.[0] ?? '')).replace(/["']/g, '').replace(/`$/, '')
}
const holdsData = (word: string): boolean => urlCarriesData(word) || SHELL_VALUE.test(word)
const SHELL_HOST = 'a host the shell fills in'

const bashAccesses = (raw: string, cwd: string, home: string): Access[] => {
  const command = joinLines(withoutHeredocs(raw)).replace(QUOTED_HOME, '$HOME')
  const substituted = [...command.matchAll(DOUBLE_QUOTED)].flatMap(q => [...q[1].matchAll(SUBSTITUTION)].map(m => m[1] ?? m[2] ?? ''))
  const parsed = [command, ...substituted].flatMap(segments).map((segment): Parsed => ({ segment, words: tokens(segment) }))
  const fed = XARGS.test(command)
  const touched = parsed.flatMap(p => segmentAccesses(p, cwd, home, fed))
  const programs = parsed.map(p => programName(program(p.words).name))
  const sender = NETWORK_TOOL.exec(command)?.[1] ?? programs.find(name => NETWORK_PROGRAMS.includes(name))
  if (!sender) return touched
  // Uploads and shells carry data; a curl or wget carries it only through the URL.
  const carries = uploadsData(command) || UPLOADER.test(command) || programs.some(name => UPLOAD_PROGRAMS.includes(name))
  const urlWords = [...[...command.matchAll(URLS)].map(m => shellWord(command, m)), ...bareUrls(parsed).map(word => `https://${word}`)]
  const dataHosts = new Set(urlWords.filter(holdsData).flatMap(hostsOf))
  const shellHost = urlWords.some(word => !hostOf(word) && word.includes('$') && holdsData(word))
  return [
    ...touched,
    ...bashHosts(command, parsed, urlWords).map((host): Access => ({ kind: carries || dataHosts.has(host) ? 'send' : 'fetch', host, via: sender })),
    ...(shellHost ? [{ kind: 'send', host: SHELL_HOST, via: sender } satisfies Access] : []),
  ]
}

// An MCP tool may post its other arguments to the URL it is given: a string long enough to hold a secret,
// anything that names a file, or a large input makes every URL in the call a send.
const MCP_PAYLOAD_CHARS = 16
const MCP_INPUT_CHARS = 200
const URL_START = new RegExp(`^${URL_PREFIX}`, 'i')
const NAMES_A_FILE = /[/.~]/

// WebFetch and most MCP servers use the WHATWG parser, so it names the host, unless it says local where the pattern, which also reads as curl does, says otherwise.
const urlHost = (url: string): string | undefined => {
  const pattern = hostOf(url)
  try {
    const parsed = new URL(url).hostname
    return !parsed || parsed === pattern?.toLowerCase() || isLocalHost(parsed) ? pattern ?? parsed : parsed
  } catch {
    return pattern
  }
}

// A string that is only a URL is judged as one; text that merely starts with one is data like any other.
const isBareUrl = (s: string): boolean => URL_START.test(s) && !/\s/.test(s) && Boolean(urlHost(s))

// Input nested too deep to serialise is large by any measure.
const inputChars = (input: unknown): number => {
  try {
    return (JSON.stringify(input) ?? '').length
  } catch {
    return Infinity
  }
}

const mcpCarriesData = (input: unknown, strings: readonly string[]): boolean => {
  const urlChars = strings.filter(isBareUrl).reduce((n, s) => n + s.length, 0)
  return strings.some(s => (isBareUrl(s) ? urlCarriesData(s) : s.length >= MCP_PAYLOAD_CHARS || NAMES_A_FILE.test(s))) ||
    inputChars(input) - urlChars > MCP_INPUT_CHARS || urlChars > 4 * URL_MAX_CHARS
}

const mcpAccesses = (toolName: string, input: unknown, cwd: string, home: string): Access[] => {
  const out: Access[] = []
  // No budget: padding must not push a URL out of view, and JSON.stringify below walks the whole input anyway.
  // A URL parser, and so most servers, ignores control characters and spaces around a URL.
  const strings = stringsOf(input, Infinity, Infinity).map(s => s.replace(/^[\0- ]+/, '').trimEnd())
  const carries = mcpCarriesData(input, strings)
  for (const s of strings) {
    const url = URL_START.test(s) ? urlHost(s) : undefined
    if (url) out.push({ kind: carries ? 'send' : 'fetch', host: url, via: toolName })
    else if (s.startsWith('/') || HOME_FORM.test(s)) out.push({ kind: 'read', path: expandPath(s, cwd, home) ?? s, via: toolName })
  }
  return out
}

// The directory part of a glob pattern: everything before the first segment with a wildcard.
const globBase = (pattern: string, cwd: string, home: string): string => {
  const parts = pattern.split('/')
  const i = parts.findIndex(p => /[*?[{]/.test(p))
  const base = (i < 0 ? parts : parts.slice(0, i)).join('/')
  return expandPath(base || '.', cwd, home) ?? resolve(cwd, base || '.')
}

export const accesses = (toolName: string, input: unknown, cwd: string, home = homedir()): Access[] => {
  const i = asRecord(input)
  const text = (key: string): string | undefined => (typeof i[key] === 'string' ? i[key] : undefined)
  const file = (key: string, kind: 'read' | 'write'): Access[] => {
    const path = text(key)
    return path ? [{ kind, path: resolve(cwd, path), via: toolName }] : []
  }
  switch (toolName) {
    case 'Read': return file('file_path', 'read')
    case 'Edit': case 'Write': case 'MultiEdit': return file('file_path', 'write')
    case 'NotebookEdit': return file('notebook_path', 'write')
    case 'Glob': case 'Grep': {
      const path = text('path')
      const pattern = text('pattern') ?? ''
      const base = path ? resolve(cwd, expandPath(path, cwd, home) ?? path) : pattern.startsWith('/') || HOME_FORM.test(pattern) ? globBase(pattern, cwd, home) : cwd
      return [{ kind: 'read', path: base, via: toolName }]
    }
    case 'Bash': return bashAccesses(text('command') ?? '', cwd, home)
    // A message a self-running agent posts to a chat app carries data out like any upload.
    case 'Send': {
      const channel = text('channel') ?? 'a chat app'
      return [{ kind: 'send', host: CHANNEL_HOSTS[channel.toLowerCase()] ?? channel, via: toolName }]
    }
    case 'InlineCode': return [{ kind: 'inline-code', path: cwd, via: toolName }]
    // A patch (Codex, OpenClaw) writes every file it names in an Add, Update or Delete header.
    case 'Patch': return [...(text('patch') ?? '').matchAll(PATCH_FILE)].map((m): Access => ({ kind: 'write', path: resolve(cwd, expandPath(m[1], cwd, home) ?? m[1]), via: toolName }))
    case 'WebFetch': {
      const url = text('url') ?? ''
      const host = urlHost(url)
      return host ? [{ kind: urlCarriesData(url) ? 'send' : 'fetch', host, via: toolName }] : []
    }
    default: return toolName.startsWith('mcp__') ? mcpAccesses(toolName, input, cwd, home) : []
  }
}
