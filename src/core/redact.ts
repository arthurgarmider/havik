const REDACTED = '[REDACTED]'

// Every quantifier below is bounded, so hostile text cannot make a pattern backtrack for long.

// Tokens that are secrets on their own: the whole match is replaced. The name says what kind it is.
const WHOLE_TOKENS: ReadonlyArray<readonly [string, RegExp]> = [
  ['private key block', /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)/g],
  ['API key', /\b(?:sk|rk)-[A-Za-z0-9_-]{16,300}/g],
  ['Stripe key', /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,300}/g],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{16,300}/g],
  ['GitHub token', /\bgithub_pat_[A-Za-z0-9_]{20,300}/g],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{16,300}/g],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,300}/g],
  ['npm token', /\bnpm_[A-Za-z0-9]{20,300}/g],
  ['Hugging Face token', /\bhf_[A-Za-z0-9]{20,300}/g],
  ['PyPI token', /\bpypi-[A-Za-z0-9_-]{16,300}/g],
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['Google OAuth token', /\bya29\.[A-Za-z0-9_-]{20,300}/g],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_-]{16,100}\.[A-Za-z0-9_-]{16,100}/g],
  ['JWT', /\beyJ[A-Za-z0-9_-]{8,500}\.[A-Za-z0-9_-]{8,500}\.[A-Za-z0-9_-]{8,500}/g],
  ['Slack webhook', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{10,200}/g],
  ['Discord webhook', /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{1,30}\/[A-Za-z0-9_-]{10,200}/g],
]
const WHOLE_TOKEN_PATTERNS: readonly RegExp[] = WHOLE_TOKENS.map(([, re]) => re)

// Credentials in a recognisable form next to a label: keep the label, replace the value.
const LABELLED: ReadonlyArray<readonly [string, RegExp, string]> = [
  ['Bearer token', /(\bBearer\s{1,10})[A-Za-z0-9_\-.]{8,500}/g, `$1${REDACTED}`],
  ['password in a URL', /(\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:/@]{1,200}:)[^\s@/]{1,500}(?=@)/gi, `$1${REDACTED}`],
  ['credential in a URL parameter', /([?&](?:token|key|api_key|apikey|access_token|secret|password|passwd|auth)=)[^&\s"']{1,500}/gi, `$1${REDACTED}`],
]
const LABELLED_CREDENTIALS: ReadonlyArray<readonly [RegExp, string]> = LABELLED.map(([, re, to]) => [re, to] as const)

const SECRET_WORDS = '(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)'
const LABEL = `${SECRET_WORDS}[\\w-]{0,40}["']?\\s{0,3}[:=]\\s{0,3}`

// Guesses: worth redacting, too noisy to report as a finding, so containsSecret ignores them.
const GUESSED_CREDENTIALS: ReadonlyArray<readonly [RegExp, string]> = [
  // A long unlabelled value after KEY= (a quote may come first).
  [/(\b[A-Za-z_][A-Za-z0-9_]{0,100}=["']?)[A-Za-z0-9_\-+/.]{32,500}/g, `$1${REDACTED}`],
  // Headers and flags that carry a credential: Authorization: token x, X-Api-Key: x, --password x, curl -u user:pw.
  [/(\b(?:authorization|x-api-key|api-key|x-auth-token|x-access-token)["']?\s{0,3}[:=]\s{0,3}["']?(?:(?:bearer|basic|token)\s{1,10})?)[A-Za-z0-9_\-.+/=]{8,500}/gi, `$1${REDACTED}`],
  [/((?<![\w-])--?(?:password|passwd|pwd|token|secret|api-?key|apikey|auth-?token|access-?token)(?:=|\s{1,3}))(?![$<-])[^\s"'`]{1,500}/gi, `$1${REDACTED}`],
  [/(\bcurl\b[^\n]{0,300}?\s-u\s{1,3}[^\s:$]{1,100}:)(?!\$)[^\s"'`]{1,500}/gi, `$1${REDACTED}`],
  // label = "quoted value", in any language, JSON or YAML.
  [new RegExp(`(${LABEL})(["'])(?![\\s$<{])[^"'\\n]{6,300}\\2`, 'gi'), `$1$2${REDACTED}$2`],
  // label = a bare value with a digit in it.
  [new RegExp(`(${LABEL})(?![$<{"'\\[])(?=[^\\s"'\`,;)}\\]]{0,300}\\d)[^\\s"'\`,;)}\\]]{8,300}(?=[\\s,;)}\\]"'\`]|$)`, 'gi'), `$1${REDACTED}`],
  // password = a bare word.
  [/(\b(?:password|passwd)\s{0,3}[:=]\s{0,3})(?![$<{"'[])[^\s"'`,;(){}[\]]{6,300}(?=[\s,;]|$)/gi, `$1${REDACTED}`],
]

const redactWith = (text: string, labelled: ReadonlyArray<readonly [RegExp, string]>): string => {
  const whole = WHOLE_TOKEN_PATTERNS.reduce((acc, re) => acc.replace(re, REDACTED), text)
  return labelled.reduce((acc, [re, to]) => acc.replace(re, to), whole)
}

export const redactSecrets = (text: string): string => redactWith(text, [...LABELLED_CREDENTIALS, ...GUESSED_CREDENTIALS])

export const containsSecret = (text: string): boolean => redactWith(text, LABELLED_CREDENTIALS) !== text

// Which recognised secret formats a text holds. String.search ignores lastIndex, so the global patterns are safe here.
export const secretKinds = (text: string): string[] =>
  [...new Set([...WHOLE_TOKENS, ...LABELLED].filter(([, re]) => text.search(re) >= 0).map(([name]) => name))]

// Every recognised secret in a text, with its kind. In-process only: callers judge the value and never store it.
export const secretMatches = (text: string): Array<{ kind: string; value: string }> =>
  [...WHOLE_TOKENS.map(([kind, re]) => [kind, re, 0] as const), ...LABELLED.map(([kind, re]) => [kind, re, 1] as const)]
    .flatMap(([kind, re, group]) => [...text.matchAll(re)].map(m => ({ kind, value: group === 0 ? m[0] : m[0].slice(m[1].length), index: m.index ?? 0 })))
    .sort((a, b) => a.index - b.index)
    .map(({ kind, value }) => ({ kind, value }))

// Documentation and test fixtures use tokens that say so: EXAMPLE, CANARY, FAKE, a counting or repeated body.
const PLACEHOLDER = /EXAMPLE|CANARY|FAKE|DUMMY|SAMPLE|PLACEHOLDER|CHANGEME|XXXX|YOUR[_-]?(?:KEY|TOKEN)|0123456789|abcdefghij|(.)\1{7,}/i
export const isPlaceholder = (value: string): boolean => PLACEHOLDER.test(value)

