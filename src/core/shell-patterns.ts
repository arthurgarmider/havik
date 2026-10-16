// What a shell string does, judged by its text. Shared by hooks, MCP command lines and skill scripts.
const SHELL = '(?:ba|z|da|k)?sh'
const PIPE_TO_SHELL = new RegExp([
  String.raw`\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?${SHELL}\b`, // curl ... | sh
  String.raw`\b${SHELL}\s+(?:-\w+\s+)*["']?\$\(\s*(?:curl|wget)\b`, // sh -c "$(curl ...)"
  String.raw`(?:\b${SHELL}|\bsource|(?:^|[\s;&|])\.)\s+<\(\s*(?:curl|wget)\b`, // bash <(curl ...), source <(curl ...)
].join('|'), 'i')
const NETWORK_UPLOAD = /\b(?:curl|wget)\b[^|;&\n]*(?:\s-d\b|\s--data(?:-[a-z]+)?\b|\s-F\b|\s-T\b|\s--upload-file\b|\s--post-(?:data|file)\b)|\b(?:nc|ncat|netcat)\s/i
const OBFUSCATED_EXEC = /\bbase64\s+(?:-d|--decode)\b|\|\s*base64\b|\beval\s*[(`$]/i
const SENSITIVE_PATH = /\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\/etc\/(?:passwd|shadow)\b|\.aws\/credentials|\.gnupg\b|\.kube\/config|\.netrc\b|\.npmrc\b/i

// Hostile input can make a regex backtrack, so long text is checked in overlapping windows instead of whole.
const WINDOW = 4000
const OVERLAP = 400
export const windows = (text: string): string[] => {
  if (text.length <= WINDOW) return [text]
  const out: string[] = []
  for (let i = 0; i < text.length; i += WINDOW - OVERLAP) out.push(text.slice(i, i + WINDOW))
  return out
}

export const isDangerousExec = (cmd: string): boolean =>
  windows(cmd).some(w => PIPE_TO_SHELL.test(w) || NETWORK_UPLOAD.test(w) || OBFUSCATED_EXEC.test(w))

export const touchesSensitivePath = (cmd: string): boolean => windows(cmd).some(w => SENSITIVE_PATH.test(w))

export const uploadsData = (cmd: string): boolean => windows(cmd).some(w => NETWORK_UPLOAD.test(w))
