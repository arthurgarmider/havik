import { describe, it, expect } from 'bun:test'
import { listProcesses, parsePs } from '../../src/agents/processes'

const COMM = [
  '  101     1 /Applications/Cursor.app/Contents/MacOS/Cursor',
  '  102   101 /Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)',
  '  103   101 /usr/local/bin/node',
  '  104     1 /opt/homebrew/bin/python3.12',
  '  105   103 /bin/zsh',
].join('\n')
const ARGS = [
  '  101 /Applications/Cursor.app/Contents/MacOS/Cursor --type=renderer',
  '  102 /Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer) --flag',
  '  103 /usr/local/bin/node /Users/u/.npm/_npx/abc/node_modules/firecrawl-mcp/dist/index.js --api-key fc-CANARYCANARYCANARY0123',
  '  104 /opt/homebrew/bin/python3.12 -m hermes_cli.main gateway --token CANARYTOKEN',
  '  105 /bin/zsh -c echo CANARY',
].join('\n')

describe('parsePs', () => {
  const procs = parsePs(COMM, ARGS)

  it('keeps the program name, its parent and the script a runner runs, never an argument', () => {
    expect(procs.map((p) => `${p.pid}:${p.ppid}:${p.exe}:${p.script ?? ''}`)).toEqual([
      '101:1:Cursor:', '102:101:Claude Helper (Renderer):', '103:101:node:index.js', '104:1:python3.12:hermes_cli.main', '105:103:zsh:',
    ])
    expect(JSON.stringify(procs)).not.toContain('CANARY')
  })

  it('names the package a node script lives in, for tool servers started with npx', () => {
    expect(procs.find((p) => p.pid === 103)?.pkg).toBe('firecrawl-mcp')
  })

  it('ignores lines it cannot read', () => {
    expect(parsePs('garbage\n  7 x\n', '')).toEqual([])
  })
})

describe('listProcesses', () => {
  it('says it did not look on Windows instead of reporting nothing running', async () => {
    const r = await listProcesses('win32')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toContain('Windows')
  })

  it('lists this machine\'s processes, including this test', async () => {
    const r = await listProcesses()
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.value.some((p) => p.pid === process.pid)).toBe(true)
  })
})
