import { describe, it, expect, afterEach } from 'bun:test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DEFAULTS } from '../../src/core/sensitivity'
import { DEFAULT_CONFIG, authorizedRoots, guardMap, havikHome, judgePath, loadGuardConfig, type GuardConfig } from '../../src/guard/policy'
import { withTree } from '../helpers/tmp-tree'

const HOME = '/home/u'
const CWD = '/home/u/proj'
const ctx = (config: GuardConfig = DEFAULT_CONFIG) => ({ roots: authorizedRoots(CWD, [], config, HOME), config, map: guardMap(DEFAULTS, config), home: HOME })
const judge = (path: string, config?: GuardConfig) => {
  const v = judgePath(path, ctx(config))
  return `${v.level}${v.authorized ? ' authorized' : ''}`
}

describe('havikHome', () => {
  const saved = process.env.HAVIK_HOME
  afterEach(() => { if (saved === undefined) delete process.env.HAVIK_HOME; else process.env.HAVIK_HOME = saved })
  it('is HAVIK_HOME when set, else ~/.havik', () => {
    process.env.HAVIK_HOME = '/tmp/hh'
    expect(havikHome()).toBe('/tmp/hh')
    delete process.env.HAVIK_HOME
    expect(havikHome().endsWith('/.havik')).toBe(true)
  })
})

describe('judgePath', () => {
  it('rates credential stores outside the project by the scanner map', () => {
    expect(judge('/home/u/.ssh/id_rsa')).toBe('critical')
    expect(judge('/home/u/.config/gh/hosts.yml')).toBe('critical')
    expect(judge('/home/u/.claude/projects/x/s.jsonl')).toBe('critical')
    expect(judge('/home/u/other/.env')).toBe('high')
  })

  it('demotes neighbouring repositories and app configs to medium, and adds shell rc files at high (R5)', () => {
    expect(judge('/home/u/git/other-repo/src/a.ts')).toBe('medium')
    expect(judge('/home/u/.config/someapp/settings.json')).toBe('medium')
    expect(judge('/home/u/.zshrc')).toBe('high')
    expect(judge('/home/u/.gitconfig')).toBe('high')
  })

  it('authorizes the project, temp dirs and the Claude Code files the agent reads all day', () => {
    expect(judge('/home/u/proj/src/a.ts')).toBe('low authorized')
    expect(judge(join(tmpdir(), 'x'))).toBe('low authorized')
    expect(judge('/home/u/.claude/settings.json')).toBe('low authorized')
    expect(judge('/home/u/.claude/skills/s/SKILL.md')).toBe('low authorized')
  })

  it('still records secrets files inside the project, at medium', () => {
    expect(judge('/home/u/proj/.env')).toBe('medium')
    expect(judge('/home/u/proj/certs/dev.key')).toBe('medium')
  })

  it('guard.yaml roots authorize extra directories, and allow authorizes exact paths', () => {
    const config = { ...DEFAULT_CONFIG, roots: ['/home/u/shared'], allow: ['/home/u/.config/gh/hosts.yml'] }
    expect(judge('/home/u/shared/.ssh-like/notes.txt', config)).toBe('low authorized')
    expect(judge('/home/u/.config/gh/hosts.yml', config)).toBe('low authorized')
  })

  it('treats ordinary system paths as low', () => {
    expect(judge('/usr/lib/node_modules/x/index.js')).toBe('low')
  })
})

describe('loadGuardConfig', () => {
  it('returns the defaults without a file or with invalid YAML', async () => {
    await withTree({}, async (dir) => expect(await loadGuardConfig(dir)).toEqual(DEFAULT_CONFIG))
    await withTree({ 'guard.yaml': 'roots: [unclosed' }, async (dir) => expect(await loadGuardConfig(dir)).toEqual(DEFAULT_CONFIG))
  })

  it('reads roots, allow, extra patterns, the alert level and retention', async () => {
    const yaml = "roots: ['~/work/shared', 3]\nallow: ['/home/u/.netrc']\nsensitive:\n  critical:\n    - { pattern: '~/Vault/', reason: 'export' }\n    - { reason: 'no pattern' }\nalert_level: critical\nretention_days: 7\n"
    await withTree({ 'guard.yaml': yaml }, async (dir) => {
      const c = await loadGuardConfig(dir)
      expect(c.roots).toEqual([join(process.env.HOME ?? '', 'work/shared')])
      expect(c.allow).toEqual(['/home/u/.netrc'])
      expect(c.sensitive.critical).toEqual([{ pattern: '~/Vault/', reason: 'export' }])
      expect(c.alertLevel).toBe('critical')
      expect(c.retentionDays).toBe(7)
    })
  })

  it('ignores an alert level or retention it does not understand', async () => {
    await withTree({ 'guard.yaml': 'alert_level: loud\nretention_days: -3\n' }, async (dir) => {
      const c = await loadGuardConfig(dir)
      expect([c.alertLevel, c.retentionDays]).toEqual(['high', 30])
    })
  })
})

describe('judgePath: real-session noise', () => {
  it('anchors ~/ patterns at the home directory, so a project .claude folder is not ~/.claude', () => {
    expect(judge('/srv/repo/.claude/settings.json')).toBe('low')
    expect(judge('/home/u/work/repo/.claude/worktrees/x/a.ts')).toBe('low')
    expect(judge('/home/u/.claude/projects/p/s.jsonl')).toBe('critical')
  })

  it('authorizes the memory notes Claude Code keeps per project', () => {
    expect(judge('/home/u/.claude/projects/-home-u-proj/memory/MEMORY.md')).toBe('low authorized')
  })
})

describe('judgePath: files that live next to secrets but are not secrets', () => {
  it('rates SSH config, known hosts, public keys and the AWS config at medium', () => {
    for (const p of ['/home/u/.ssh/config', '/home/u/.ssh/known_hosts', '/home/u/.ssh/id_ed25519.pub', '/home/u/.aws/config']) expect(judge(p)).toBe('medium')
    expect(judge('/home/u/.ssh/id_ed25519')).toBe('critical')
    expect(judge('/home/u/.aws/credentials')).toBe('critical')
  })

  it('authorizes the session\'s own transcript and the memory directory, but not other transcripts', () => {
    const own = '/home/u/.claude/projects/p/own.jsonl'
    const c = { ...ctx(), roots: [...ctx().roots, own] }
    expect(judgePath(own, c).authorized).toBe(true)
    expect(judgePath('/home/u/.claude/projects/p/other.jsonl', c)).toMatchObject({ level: 'critical', authorized: false })
  })
})

describe('judgePath: Claude Code session files', () => {
  it('authorizes the files of the session itself, rates other transcripts critical and other artifacts medium', () => {
    const own = { ...ctx(), sessionId: 'abc-123' }
    expect(judgePath('/home/u/.claude/projects/p/abc-123/subagents/a.jsonl', own).authorized).toBe(true)
    expect(judgePath('/home/u/.claude/projects/p/abc-123.jsonl', own).authorized).toBe(true)
    expect(judgePath('/home/u/.claude/projects/p/other-9/subagents/a.jsonl', own)).toMatchObject({ level: 'critical', authorized: false })
    expect(judgePath('/home/u/.claude/projects/p/other-9/research/paper.pdf', own)).toMatchObject({ level: 'medium', authorized: false })
    expect(judgePath('/home/u/.claude/plans/x.md', own).level).toBe('medium')
  })
})

describe('judgePath: the rest of ~/.claude', () => {
  it('keeps credentials, history and debug logs critical, and rates other application data medium', () => {
    expect(judge('/home/u/.claude/.credentials.json')).toBe('critical')
    expect(judge('/home/u/.claude/history.jsonl')).toBe('critical')
    expect(judge('/home/u/.claude/debug/latest.log')).toBe('critical')
    expect(judge('/home/u/.claude/kickback/ledger.jsonl')).toBe('medium')
    expect(judge('/home/u/.claude/shell-snapshots/snap.sh')).toBe('medium')
  })
})

describe('judgePath: a session started in the home directory or at /', () => {
  const at = (cwd: string) => ({ roots: authorizedRoots(cwd, [], DEFAULT_CONFIG, HOME), config: DEFAULT_CONFIG, map: guardMap(DEFAULTS, DEFAULT_CONFIG), home: HOME })
  it('does not authorize every credential under it', () => {
    for (const cwd of [HOME, '/', '/home']) {
      expect(judgePath('/home/u/.ssh/id_rsa', at(cwd))).toMatchObject({ level: 'critical', authorized: false })
      expect(judgePath('/home/u/.aws/credentials', at(cwd))).toMatchObject({ level: 'critical', authorized: false })
    }
  })
})

describe('judgePath: a credential directory itself', () => {
  it('rates the directory as its contents are rated', () => {
    expect(judge('/home/u/.ssh')).toBe('critical')
    expect(judge('/home/u/.aws')).toBe('critical')
  })

  it('rates ~/.claude itself as the application data it mostly holds (found by replay)', () => {
    expect(judge('/home/u/.claude')).toBe('medium')
  })
})

describe('judgePath: every agent\'s files', () => {
  const as = (agent: string | undefined, sessionId?: string) => ({ ...ctx(), roots: authorizedRoots(CWD, [], DEFAULT_CONFIG, HOME, agent), agent, sessionId })
  const verdict = (path: string, agent?: string, sessionId?: string) => {
    const v = judgePath(path, as(agent, sessionId))
    return `${v.level}${v.authorized ? ' authorized' : ''}: ${v.reason}`
  }

  it('rates any agent\'s password or key file critical, even for that agent', () => {
    expect(verdict('/home/u/.codex/auth.json', 'codex')).toBe("critical: Codex's password or key file")
    expect(verdict('/home/u/.hermes/.env', 'claude-code')).toBe("critical: Hermes Agent's password or key file")
    expect(verdict('/home/u/.junie/instances/a.json', 'codex')).toBe("critical: JetBrains AI agents' password or key file")
  })

  it('rates another agent\'s conversations and settings critical, the rest of its data medium', () => {
    expect(verdict('/home/u/.claude/projects/p/s.jsonl', 'cursor')).toBe("critical: Claude Code's conversations")
    expect(verdict('/home/u/.cursor/projects/x/agent-transcripts/a.jsonl', 'codex')).toBe("critical: Cursor's conversations")
    expect(verdict('/home/u/.codex/config.toml', 'cursor')).toBe("critical: Codex's settings, which can hold tokens")
    expect(verdict('/home/u/.hermes/logs/gateway.log', 'codex')).toBe('medium: Hermes Agent application data')
    expect(verdict('/home/u/.gemini/config/hooks.json', 'codex')).toBe('medium: Antigravity application data')
  })

  it('treats Cursor\'s per-project working files as its own, and only its transcripts as conversations', () => {
    expect(verdict('/home/u/.cursor/projects/p/terminals/1.txt', 'cursor')).toBe("low authorized: Cursor's own files")
    expect(verdict('/home/u/.cursor/projects/p/agent-transcripts/a/b.jsonl', 'cursor', 'c1')).toBe("critical: Cursor's other conversations")
    expect(verdict('/home/u/.cursor/projects/p/terminals/1.txt', 'codex')).toBe('medium: Cursor application data')
    expect(verdict('/home/u/.cursor/projects/p/agent-transcripts/a/b.jsonl', 'codex')).toBe("critical: Cursor's conversations")
  })

  it('lets an agent use its own files, but not its other conversations', () => {
    expect(verdict('/home/u/.codex/skills/a/SKILL.md', 'codex')).toBe("low authorized: Codex's own files")
    expect(verdict('/home/u/.codex/sessions/2026/10/16/rollout-abc.jsonl', 'codex', 'abc')).toBe("low authorized: Codex's own files")
    expect(verdict('/home/u/.codex/sessions/2026/10/01/rollout-zzz.jsonl', 'codex', 'abc')).toBe("critical: Codex's other conversations")
  })

  it('keeps Claude Code\'s own rules for Claude Code, and authorizes its everyday files for it alone', () => {
    expect(verdict('/home/u/.claude/projects/-home-u-proj/memory/MEMORY.md')).toBe('low authorized: Claude Code memory notes')
    expect(verdict('/home/u/.claude/projects/-home-u-proj/memory/MEMORY.md', 'cursor')).toBe("critical: Claude Code's conversations")
    expect(verdict('/home/u/.claude/settings.json', 'claude-code')).toBe('low authorized: inside the project')
    expect(verdict('/home/u/.claude/settings.json', 'cursor')).toBe('medium: Claude Code application data')
  })
})

describe('judgePath: a password file is never "inside the project"', () => {
  it('rates an agent\'s key file critical even when the session runs in that agent\'s folder', () => {
    const c = { ...ctx(), roots: authorizedRoots('/home/u/.codex', [], DEFAULT_CONFIG, HOME, 'codex'), agent: 'codex' }
    expect(judgePath('/home/u/.codex/auth.json', c)).toMatchObject({ level: 'critical', authorized: false })
  })
})
