import { describe, it, expect } from 'bun:test'
import { accessLine, findingLine } from '../../src/guard/format'
import type { HookEvent } from '../../src/guard/types'

const event: HookEvent = { hook_event_name: 'PreToolUse', session_id: 's', cwd: '/p', tool_name: 'WebFetch' }
const TOKEN = 'ghp_CANARYCANARYCANARYCANARYCANARY123456'

describe('audit lines', () => {
  it('redact a host, as they redact every other string', () => {
    const f = { detector: 'data-leaving', severity: 'high', key: 'k', message: 'm', label: 'l', evidence: 'observed', host: `${TOKEN}@h.example` } as const
    expect(JSON.stringify(findingLine(event, f as never, false, 1))).not.toContain('CANARY')
    expect(JSON.stringify(accessLine(event, { kind: 'send', host: `${TOKEN}@h.example`, via: 'WebFetch' }, 1))).not.toContain('CANARY')
  })
})
