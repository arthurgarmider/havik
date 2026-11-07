// What a shell string does, judged by its text. Shared by hooks, MCP command lines and skill scripts.
const SHELL = '(?:ba|z|da|k)?sh'
const PIPE_TO_SHELL = new RegExp([
  String.raw`\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?${SHELL}\b`, // curl ... | sh
  String.raw`\b${SHELL}\s+(?:-\w+\s+)*["']?\$\(\s*(?:curl|wget)\b`, // sh -c "$(curl ...)"
  String.raw`(?:\b${SHELL}|\bsource|(?:^|[\s;&|])\.)\s+<\(\s*(?:curl|wget)\b`, // bash <(curl ...), source <(curl ...)
].join('|'), 'i')
const OBFUSCATED_EXEC = /\bbase64\s+(?:-d|--decode)\b|\|\s*base64\b|\beval\s*[(`$]/i
const SENSITIVE_PATH = /\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\/etc\/(?:passwd|shadow)\b|\.aws\/credentials|\.gnupg\b|\.kube\/config|\.netrc\b|\.npmrc\b/i

const startsComment = (text: string, i: number): boolean => text[i] === '#' && (i === 0 || /[\s;&|(]/.test(text[i - 1]))

// A backslash at the end of a line joins the next line to it, as the shell does, unless it is itself escaped, in single quotes or in a comment, which ends at the newline.
export const joinLines = (text: string): string => {
  if (!text.includes('\\')) return text
  let out = ''
  let quote: string | undefined
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quote === "'") {
      if (c === "'") quote = undefined
      out += c
    } else if (c === '\\') {
      const eol = text[i + 1] === '\n' ? 1 : text[i + 1] === '\r' && text[i + 2] === '\n' ? 2 : 0
      if (eol === 0) out += c + (text[i + 1] ?? '')
      i += eol || 1
    } else if (!quote && startsComment(text, i)) {
      const end = text.indexOf('\n', i)
      const stop = end < 0 ? text.length : end
      out += text.slice(i, stop)
      i = stop - 1
    } else {
      if (c === '"' || (c === "'" && !quote)) quote = quote ? undefined : c
      out += c
    }
  }
  return out
}

// Splits a command at `;`, `|`, `&`, `&&`, `||` and newlines outside quotes, and drops comments.
export const segments = (command: string): string[] => {
  const out: string[] = []
  let current = ''
  let quote: string | undefined
  let quoteAt = 0
  for (let i = 0; i < command.length; i++) {
    const c = command[i]
    if (quote) {
      if (c === '\\' && quote === '"') { current += c + (command[i + 1] ?? ''); i++; continue }
      if (c === quote) quote = undefined
      current += c
      continue
    }
    if (c === '\\') { current += c + (command[i + 1] ?? ''); i++; continue }
    if (c === "'" || c === '"') { quote = c; quoteAt = current.length; current += c; continue }
    if (startsComment(command, i)) {
      const end = command.indexOf('\n', i)
      i = (end < 0 ? command.length : end) - 1
      continue
    }
    // A lone & ends a command too, except in a redirect: 2>&1, >&2, &>file.
    const background = c === '&' && command[i - 1] !== '>' && command[i - 1] !== '<' && command[i + 1] !== '>'
    if (c === '\n' || c === ';' || c === '|' || background) {
      out.push(current)
      current = ''
      if ((c === '&' || c === '|') && command[i + 1] === c) i++
      continue
    }
    current += c
  }
  // A quote that never closes is not one: what follows is read again without it. No later quote of its kind can close either, so this happens at most once per kind.
  if (quote) return [...out, ...segments(`${current.slice(0, quoteAt)} ${current.slice(quoteAt + 1)}`)]
  out.push(current)
  return out
}

// A program name matches in any case, as a case-insensitive filesystem runs it; a flag never does: curl -d sends a body, curl -D saves the headers.
const TRANSFER_TOOL = /\b(?:curl|wget|nc|ncat|netcat)\b/i
const NETCAT = /\b(?:nc|ncat|netcat)\s/i
// curl's short flags that take no value. They run together in front of one that does (-sd, -fsSLT), and that one takes the rest of the word: -ofile.d only names a file.
export const CURL_NO_VALUE = '[0-46:#aBfgGiIjJklLMnNOpqRsSvVZ]'
// A config file (-K) can hold any of these. The other --expand- forms, such as --expand-url, carry nothing by themselves.
const CURL_LONG = String.raw`--(?:expand-)?(?:data(?:-[a-z]+)?|form(?:-string)?|json|upload-file|url-query|config)(?=[\s"'=]|$)`
const CURL_UPLOAD = new RegExp(String.raw`\s["']?(?:-${CURL_NO_VALUE}*[dFTK]|${CURL_LONG})`)
// In free text a value joined to the flag cannot be told from a word such as -Total, so only the shapes of a value count.
const CURL_UPLOAD_IN_TEXT = new RegExp(String.raw`\s["']?(?:-${CURL_NO_VALUE}*[dFTK](?=[\s"'@=./~]|$)|${CURL_LONG})`)
// wget's -d, -F and -T are debug, force-html and timeout; only these long flags send a body.
const WGET_UPLOAD = /\s["']?--(?:post|body)-(?:data|file)\b/
// Or the same setting given with -e, whose names ignore case, - and _.
const WGET_SETTING = /\s["']?(?:-[46bcdEFhHkKLmNpqrSvVx]*e|--execute)[=\s]*["']?(?:post|body)[-_]?(?:data|file)/i
const wgetUploads = (args: string): boolean => WGET_UPLOAD.test(args) || WGET_SETTING.test(args)

// A command in the open: its flags are what stands outside strings, a string holds a value unless it is one flag, and quotes tell where it ends.
const CURL_HERE = /\bcurl(?=[\s"'`)]|$)([\s\S]*)/i
const WGET_HERE = /\bwget(?=[\s"'`)]|$)([\s\S]*)/i
const STRING = /'[^']*'|"(?:\\[\s\S]?|[^"\\])*(?:"|$)/g
const FLAG_IN_QUOTES = /^["']-[^\s"']*["']$/
const uploadsInTheOpen = (command: string): boolean => {
  const open = command.replace(STRING, q => (FLAG_IN_QUOTES.test(q) ? q : '""'))
  return CURL_UPLOAD.test(CURL_HERE.exec(open)?.[1] ?? '') || wgetUploads(WGET_HERE.exec(open)?.[1] ?? '')
}
// A command inside a string, such as sh -c "curl ...; rm -d x" or a line of a script's source: quotes say nothing there, so it ends at the first separator.
const CURL_IN_TEXT = /\bcurl(?=[\s"'`)]|$)([^|;&\n]*)/gi
const WGET_IN_TEXT = /\bwget(?=[\s"'`)]|$)([^|;&\n]*)/gi
const uploadsInText = (text: string): boolean =>
  [...text.matchAll(CURL_IN_TEXT)].some(m => CURL_UPLOAD_IN_TEXT.test(m[1])) || [...text.matchAll(WGET_IN_TEXT)].some(m => wgetUploads(m[1]))

const isUpload = (text: string): boolean => {
  const joined = joinLines(text)
  if (!TRANSFER_TOOL.test(joined)) return false
  if (NETCAT.test(joined)) return true
  const commands = segments(joined)
  return commands.some(uploadsInTheOpen) || uploadsInText(commands.join('\n'))
}

// Hostile input can make a regex backtrack, so long text is checked in overlapping windows instead of whole.
// isUpload needs none: its patterns do not backtrack, and a window would lose a flag far from the program name.
const WINDOW = 4000
const OVERLAP = 400
export const windows = (text: string): string[] => {
  if (text.length <= WINDOW) return [text]
  const out: string[] = []
  for (let i = 0; i < text.length; i += WINDOW - OVERLAP) out.push(text.slice(i, i + WINDOW))
  return out
}

export const isDangerousExec = (cmd: string): boolean =>
  isUpload(cmd) || windows(joinLines(cmd)).some(w => PIPE_TO_SHELL.test(w) || OBFUSCATED_EXEC.test(w))

export const touchesSensitivePath = (cmd: string): boolean => windows(cmd).some(w => SENSITIVE_PATH.test(w))

export const uploadsData = isUpload
