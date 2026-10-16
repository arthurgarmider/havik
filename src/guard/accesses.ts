import { homedir } from 'node:os'
import { basename, resolve } from 'node:path'
import { hostOf } from '../core/exfil-patterns'
import { uploadsData } from '../core/shell-patterns'
import { asRecord } from '../core/json'
import type { Access } from './types'

const MAX_COMMAND = 64_000
const MAX_STRINGS = 1_000
const MAX_STRING_BYTES = 64_000

// Quoted strings and bare words; every alternative is unambiguous, so the scan is linear.
const TOKEN = /'([^']*)'|"((?:\\.|[^"\\])*)"|([^\s'"|;&<>()]+)/g
const REDIRECT = /(?:^|[^<>&\d])>{1,2}\s*('[^']*'|"(?:\\.|[^"\\])*"|[^\s;&|<>]+)/g
const NETWORK_TOOL = /(?:^|[\s;&|(])(?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|sftp|ftp|http|xh)(?=\s)/
const URLS = /\b(?:https?|ftp):\/\/[^\s'"`)]{1,2000}/g
const SCP_HOST = /(?:^|\s)(?:[\w.-]{1,64}@)?([\w-]{1,63}(?:\.[\w-]{1,63}){1,10}):(?!\/\/)/g
const HOST_LIKE = /^(?:[\w-]{1,63}\.)+[a-z][\w-]{0,62}$|^\d{1,3}(?:\.\d{1,3}){3}$/i
const RUNNER = /^(?:node|bun|deno|python[23]?|ruby|perl|php|sh|bash|zsh)$/
const INLINE_FLAG = /^-(?:c|e|p|-eval|-print)$/
const PREFIX = /^(?:sudo|exec|time|nohup|env|command|export|local|declare)$|^\w+=/
// Programs that name a path without reading its contents: a `cd` or `ls` of a credential directory is not a read.
const NON_READERS = new Set(['cd', 'ls', 'mkdir', 'rmdir', 'touch', 'stat', 'test', '[', '[[', 'echo', 'printf', 'pwd', 'which', 'du', 'df', 'find', 'tree', 'file', 'basename', 'dirname', 'realpath', 'readlink', 'chmod', 'chown', 'rm', 'ln', 'git', 'pushd', 'popd', 'open', 'code', 'xdg-open'])
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|pl|php|sh|bash|zsh|fish)$/i
const HEREDOC = /<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1/
const UPLOADER = /(?:^|[\s;&|(])(?:ssh|scp|rsync|sftp|ftp|nc|ncat|netcat)(?=\s)/
// A GET of a plain page cannot carry much; a query string or a long opaque path segment can.
const PAYLOAD_SEGMENT = /[A-Za-z0-9+/=_-]{32,}/
export const urlCarriesData = (url: string): boolean => {
  const rest = url.replace(/^[a-z]+:\/\/[^/?#]+/i, '')
  const [path, query] = rest.split(/[?#]/, 2)
  return (query !== undefined && query.length > 0) || path.split('/').some(s => PAYLOAD_SEGMENT.test(s))
}
const HOME_FORM = /^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/
const CHANNEL_HOSTS: Record<string, string> = { telegram: 'api.telegram.org', slack: 'slack.com', discord: 'discord.com', whatsapp: 'web.whatsapp.com', signal: 'signal.org', matrix: 'matrix.org' }
const PATCH_FILE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm
// ssh and its relatives use a key to authenticate; the key's contents never reach the output.
const KEY_USERS = new Set(['ssh', 'scp', 'sftp', 'rsync', 'ssh-add'])
const IDENTITY_OPTION = /^(?:-o)?IdentityFile=/i
// A command substitution inside double quotes runs like any other command.
const DOUBLE_QUOTED = /"((?:\\.|[^"\\])*)"/g
const SUBSTITUTION = /\$\(([^()]*)\)|`([^`]*)`/g
const EXEC_FLAG = /^-(?:exec|execdir|ok|okdir)$/
const XARGS = /(?:^|[\s|])xargs\s/

const tokens = (text: string): string[] => [...text.matchAll(TOKEN)].map(m => m[1] ?? m[2] ?? m[3] ?? '')

// Splits a command at `;`, `|`, `&&`, `||` and newlines that are not inside quotes.
const segments = (command: string): string[] => {
  const out: string[] = []
  let current = ''
  let quote: string | undefined
  for (let i = 0; i < command.length; i++) {
    const c = command[i]
    if (quote) {
      if (c === '\\' && quote === '"') { current += c + (command[i + 1] ?? ''); i++; continue }
      if (c === quote) quote = undefined
      current += c
      continue
    }
    if (c === "'" || c === '"') { quote = c; current += c; continue }
    if (c === '\n' || c === ';' || c === '|' || (c === '&' && command[i + 1] === '&')) {
      out.push(current)
      current = ''
      if (c === '&' || (c === '|' && command[i + 1] === '|')) i++
      continue
    }
    current += c
  }
  out.push(current)
  return out
}

export const tildify = (path: string, home = homedir()): string => (path === home || path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path)

// A token that names a file: absolute, home-relative or explicitly relative. Bare words are not paths.
export const expandPath = (raw: string, cwd: string, home = homedir()): string | undefined => {
  // --data=@f, file=@f and field=<f all name the file after the = sign.
  const t = raw.replace(/^(?:--?)?[\w.-]+=/, '').replace(/^[@<]/, '')
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
  const i = words.findIndex(w => !PREFIX.test(w))
  return i < 0 ? { name: '', rest: [] } : { name: words[i], rest: words.slice(i + 1) }
}

const SYSTEM_BIN = /^\/(?:usr|bin|sbin|opt\/homebrew)\//

const bashHosts = (command: string): string[] => {
  if (!NETWORK_TOOL.test(command)) return []
  const hosts = new Set<string>()
  for (const m of command.matchAll(URLS)) {
    const host = hostOf(m[0])
    if (host) hosts.add(host)
  }
  for (const m of command.matchAll(SCP_HOST)) hosts.add(m[1])
  for (const segment of segments(command)) {
    const { name, rest } = program(tokens(segment))
    if (!['ssh', 'nc', 'ncat', 'netcat'].includes(basename(name))) continue
    const host = rest.map(w => w.replace(/^[^@]*@/, '')).find(w => HOST_LIKE.test(w))
    if (host) hosts.add(host)
  }
  return [...hosts]
}

const bashSender = (command: string): string =>
  command.match(/(?:^|[\s;&|(])(curl|wget|nc|ncat|netcat|ssh|scp|rsync|sftp|ftp|http|xh)(?=\s)/)?.[1] ?? 'Bash'

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
const segmentAccesses = (segment: string, cwd: string, home: string, fedToReader = false): Access[] => {
  const words = tokens(segment)
  const { name, rest } = program(words)
  // A path assigned to a variable (F=~/.ssh/id_rsa) is read by whatever uses the variable next.
  const assigned = words.slice(0, words.length - rest.length).filter(w => /^\w+=./.test(w)).flatMap(w => { const p = expandPath(w.replace(/^\w+=/, ''), cwd, home); return p ? [p] : [] })
  if (!name) return assigned.map((path): Access => ({ kind: 'read', path, via: 'assignment' }))
  const via = basename(name)
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
  for (const word of rest) {
    if (!reads || word === scriptToken || writes.has(word)) continue
    const path = expandPath(word, cwd, home)
    if (path) out.push({ kind: keys.has(word) ? 'use' : 'read', path, via })
  }
  for (const word of writes) {
    const path = expandPath(word, cwd, home)
    if (path) out.push({ kind: 'write', path, via })
  }
  return out
}

// A heredoc body is data, not commands: it is dropped, the line that opens it is kept.
const withoutHeredocs = (command: string): string => {
  const out: string[] = []
  let terminator: string | undefined
  for (const line of command.split('\n')) {
    if (terminator !== undefined) {
      if (line.trim() === terminator) terminator = undefined
      continue
    }
    out.push(line)
    terminator = HEREDOC.exec(line)?.[2]
  }
  return out.join('\n')
}

// `"$HOME"/x` is one path to the shell and two tokens to the tokenizer; glue it back together first.
const QUOTED_HOME = /["']\$\{?HOME\}?["'](?=\/)/g

const bashAccesses = (raw: string, cwd: string, home: string): Access[] => {
  if (raw.length > MAX_COMMAND) return []
  const command = withoutHeredocs(raw).replace(QUOTED_HOME, '$HOME')
  const sender = bashSender(command)
  // Uploads and shells carry data; a curl or wget carries it only through the URL.
  const carries = uploadsData(command) || UPLOADER.test(command)
  const urls = new Set([...command.matchAll(URLS)].filter(m => urlCarriesData(m[0])).map(m => hostOf(m[0])))
  const substituted = [...command.matchAll(DOUBLE_QUOTED)].flatMap(q => [...q[1].matchAll(SUBSTITUTION)].map(m => m[1] ?? m[2] ?? ''))
  const fed = XARGS.test(command)
  return [
    ...[command, ...substituted].flatMap(segments).flatMap(segment => segmentAccesses(segment, cwd, home, fed)),
    ...bashHosts(command).map((host): Access => ({ kind: carries || urls.has(host) ? 'send' : 'fetch', host, via: sender })),
  ]
}

const mcpAccesses = (toolName: string, input: unknown, cwd: string, home: string): Access[] => {
  const out: Access[] = []
  for (const s of stringsOf(input)) {
    const url = s.match(/^(?:https?|ftp):\/\//) ? hostOf(s) : undefined
    if (url) out.push({ kind: 'send', host: url, via: toolName })
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
      const host = hostOf(url)
      return host ? [{ kind: urlCarriesData(url) ? 'send' : 'fetch', host, via: toolName }] : []
    }
    default: return toolName.startsWith('mcp__') ? mcpAccesses(toolName, input, cwd, home) : []
  }
}
