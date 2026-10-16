import { describe, it, expect } from 'bun:test'
import { redactSecrets, containsSecret, secretKinds } from '../../src/core/redact'

// Built at runtime: a literal token in this shape would trip secret scanning on push.
const GITLAB_TOKEN = ['glpat', 'CANARY0123456789abcd'].join('-')
const STRIPE_LIVE_KEY = ['sk', 'live', 'CANARY0123456789abcdefghij'].join('_')

describe('redactSecrets', () => {
  const secrets: Array<[string, string]> = [
    ['OpenAI-style key', 'sk-live-abcdef1234567890'],
    ['GitHub token', 'ghp_0123456789abcdefghijABCDEFGHIJ'],
    ['GitHub fine-grained token', 'github_pat_11AAAAAAA0abcdefghij_klmnopqrstuvwxyz'],
    ['Slack token', 'xoxb-1234567890-abcdefghij'],
    ['AWS access key id', 'AKIAIOSFODNN7EXAMPLE'],
    ['Google API key', 'AIzaSyA1234567890abcdefghijklmnopqrstuv'],
  ]
  for (const [name, secret] of secrets) {
    it(`redacts a ${name}`, () => {
      const out = redactSecrets(`token is ${secret} here`)
      expect(out).not.toContain(secret)
      expect(out).toContain('[REDACTED]')
    })
  }

  it('keeps the Bearer prefix and redacts the credential', () => {
    expect(redactSecrets('Authorization: Bearer abcdef1234567890')).toBe('Authorization: Bearer [REDACTED]')
  })

  it('redacts a whole private key block', () => {
    const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nmore\n-----END RSA PRIVATE KEY-----'
    expect(redactSecrets(`k=${key}!`)).toBe('k=[REDACTED]!')
  })

  it('redacts the password in URL userinfo but keeps the user and host', () => {
    expect(redactSecrets('https://user:pw123456@mcp.example.com/sse')).toBe('https://user:[REDACTED]@mcp.example.com/sse')
  })

  it('redacts credential-looking query parameters only', () => {
    expect(redactSecrets('https://a.example/x?page=2&token=tok_abcdef123456&api_key=zzz999')).toBe(
      'https://a.example/x?page=2&token=[REDACTED]&api_key=[REDACTED]',
    )
  })

  it('redacts a long KEY=value assignment but keeps the key name', () => {
    expect(redactSecrets('API_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCD')).toBe('API_KEY=[REDACTED]')
  })

  it('leaves ordinary code and prose alone', () => {
    const benign = [
      "fetch('https://example.com/a?page=2')",
      "const key = 'id'",
      'max_tokens = 100',
      'Authorization: Bearer ${process.env.SLACK_TOKEN}',
      'DEBUG=1',
    ]
    for (const line of benign) expect(redactSecrets(line)).toBe(line)
  })
})

describe('redactSecrets: formats found leaking by review', () => {
  const leaks: Array<[string, string, string]> = [
    ['Stripe live key', `charge with ${STRIPE_LIVE_KEY} now`, `${STRIPE_LIVE_KEY}`],
    ['npm token', 'npm config set //registry.npmjs.org/:_authToken npm_CANARY0123456789abcdefghijklmnopqrst', 'npm_CANARY0123456789abcdefghijklmnopqrst'],
    ['Hugging Face token', 'send the header with hf_CANARY0123456789abcdefghijklmnop now', 'hf_CANARY0123456789abcdefghijklmnop'],
    ['GitLab token', `use the token ${GITLAB_TOKEN} for the clone`, `${GITLAB_TOKEN}`],
    ['JWT', 'cookie eyJhbGciOiJIUzI1NiJ9CANARY.eyJzdWIiOiIxMjM0NTY3ODkwIn0CANARY.dBjftJeZ4CVPCANARY0123456789', 'eyJhbGciOiJIUzI1NiJ9CANARY'],
    ['Slack webhook', 'curl -X POST https://hooks.slack.com/services/T00000000/B00000000/CANARYWEBHOOK0123456789abcd', 'CANARYWEBHOOK0123456789abcd'],
    ['quoted shell export', 'export AWS_SECRET_ACCESS_KEY="CANARYAWS/0123456789+abcdefghijKLMNOPQRSTUV"', 'CANARYAWS/0123456789+abcdefghijKLMNOPQRSTUV'],
    ['YAML password', 'db:\n  password: CANARYYAMLPASSWORD', 'CANARYYAMLPASSWORD'],
    ['quoted api_key', 'config = { api_key: "CANARYYAMLAPIKEY0123", retries: 3 }', 'CANARYYAMLAPIKEY0123'],
    ['JSON secret', '{"client_secret": "CANARYJSONSECRET01"}', 'CANARYJSONSECRET01'],
    ['Authorization token scheme', 'curl -H "Authorization: token CANARYTOKEN0123456789" https://api.example', 'CANARYTOKEN0123456789'],
    ['X-Api-Key header', 'curl -H "X-Api-Key: CANARYXAPIKEY0123456789" https://api.example', 'CANARYXAPIKEY0123456789'],
    ['--password flag', 'mysql --user app --password CANARYPASSFLAG1 --host db', 'CANARYPASSFLAG1'],
    ['--token= flag', 'tool login --token=CANARYTOKENFLAG1', 'CANARYTOKENFLAG1'],
    ['curl -u', 'curl -u alice:CANARYCURLPASS1 https://api.example/x', 'CANARYCURLPASS1'],
  ]
  for (const [name, text, secret] of leaks) {
    it(`redacts a ${name}`, () => {
      const out = redactSecrets(text)
      expect(out).not.toContain(secret)
      expect(out).toContain('[REDACTED]')
    })
  }

  it('flags a token in a recognisable format, as before, but never guesses on plain assignments', () => {
    expect(containsSecret(`${STRIPE_LIVE_KEY}`)).toBe(true)
    expect(containsSecret('hf_CANARY0123456789abcdefghijklmnop')).toBe(true)
    expect(containsSecret('password: CANARYYAMLPASSWORD')).toBe(false)
    expect(containsSecret('TOKEN=abcd1234efgh')).toBe(false)
  })

  it('leaves ordinary code that merely mentions credentials alone', () => {
    const benign = [
      'const token = getToken()',
      "password = prompt('Password?')",
      'const apiKey = process.env.API_KEY',
      'token: ${{ secrets.GITHUB_TOKEN }}',
      'secret: <your-secret>',
      'api_key: YOUR_API_KEY_HERE',
      'max_tokens: 4096',
      'Authorization: Bearer ${process.env.SLACK_TOKEN}',
      "const secret = ''",
      'curl -u $USER:$PASS https://api.example',
      'tool --token $TOKEN --verbose',
      'password: ${DB_PASSWORD}',
    ]
    for (const line of benign) expect(redactSecrets(line)).toBe(line)
  })

  it('takes bounded time on text built to make a pattern backtrack', () => {
    const hostile = [
      'a-'.repeat(60_000), 'a.b-c+'.repeat(30_000), 'a://b:'.repeat(30_000), 'token'.repeat(60_000), 'password='.repeat(30_000),
      `token = "${'x'.repeat(120_000)}`, `curl ${'-u '.repeat(40_000)}`, '"='.repeat(60_000), 'Bearer '.repeat(20_000), '?token='.repeat(20_000),
      `Authorization: ${'x'.repeat(120_000)}`, 'sk-'.repeat(40_000), '-----BEGIN '.repeat(10_000), `${'a'.repeat(120_000)}=`,
    ]
    const start = performance.now()
    for (const text of hostile) redactSecrets(text)
    expect(performance.now() - start).toBeLessThan(1500)
  })
})

describe('containsSecret', () => {
  it('does not treat a long path or value assignment as a credential', () => {
    expect(containsSecret('HOME_DIR=/Users/someone/some/very/long/directory/path/here/ok')).toBe(false)
    expect(redactSecrets('HOME_DIR=/Users/someone/some/very/long/directory/path/here/ok')).toBe('HOME_DIR=[REDACTED]')
  })

  it('is true when redaction would change the text', () => {
    expect(containsSecret('Bearer abcdef1234567890')).toBe(true)
    expect(containsSecret('sk-live-abcdef1234567890')).toBe(true)
  })

  it('is false for env-var references and plain text', () => {
    expect(containsSecret('Bearer ${TOKEN}')).toBe(false)
    expect(containsSecret('hello world')).toBe(false)
  })
})

describe('secretKinds', () => {
  it('names each recognised format once', () => {
    const text = 'a ghp_0123456789abcdefghijABCDEFGHIJ and github_pat_11AAAAAAA0abcdefghij_klmnopqrstuvwxyz and AKIAIOSFODNN7EXAMPLE'
    expect(secretKinds(text).sort()).toEqual(['AWS access key', 'GitHub token'])
    expect(secretKinds('Authorization: Bearer abcdef1234567890')).toEqual(['Bearer token'])
    expect(secretKinds('-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n')).toEqual(['private key block'])
  })

  it('ignores guessed formats and ordinary text', () => {
    expect(secretKinds('password: hunter2222 and API_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCD')).toEqual([])
    expect(secretKinds('nothing to see')).toEqual([])
  })

  it('is stateless across calls, although the patterns are global', () => {
    const t = 'token ghp_0123456789abcdefghijABCDEFGHIJ'
    expect([secretKinds(t), secretKinds(t), secretKinds(t)]).toEqual([['GitHub token'], ['GitHub token'], ['GitHub token']])
  })
})

describe('secretMatches', () => {
  it('returns each match with its kind, and tells placeholders from the real thing', () => {
    const { secretMatches, isPlaceholder } = require('../../src/core/redact')
    const text = 'a AKIAIOSFODNN7EXAMPLE and ghp_CANARYCANARYCANARYCANARY0001 and npm_0123456789abcdef0123456789abcdef and ghp_9fKq2LmNpR7sTvWx1yZaBc4dEfGh5JkL'
    const found = secretMatches(text)
    expect(found.map((m: { kind: string }) => m.kind)).toEqual(['AWS access key', 'GitHub token', 'npm token', 'GitHub token'])
    expect(found.map((m: { value: string }) => isPlaceholder(m.value))).toEqual([true, true, true, false])
  })
})
