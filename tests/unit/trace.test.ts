import { describe, it, expect } from 'bun:test'
import { join } from 'path'
import { trace } from '../../src/core/trace'

describe('trace', () => {
  it('returns same result as wrapped function', () => {
    const add = trace('add', (a: number, b: number) => a + b)
    expect(add(2, 3)).toBe(5)
  })

  it('preserves async behavior', async () => {
    const asyncFn = trace('asyncFn', async (x: number) => x * 2)
    expect(await asyncFn(5)).toBe(10)
  })

  it('propagates errors', () => {
    const throws = trace('throws', () => { throw new Error('boom') })
    expect(() => throws()).toThrow('boom')
  })
})

describe('trace under HAVIK_DEBUG', () => {
  it('does not print secrets carried in its arguments', async () => {
    const trace = join(import.meta.dir, '../../src/core/trace')
    const script = `import { trace } from '${trace}'; trace('probe', (x) => x)({ headers: { Authorization: 'Bearer sk-live-abcdef1234567890' } })`
    const proc = Bun.spawn(['bun', '-e', script], { env: { ...process.env, HAVIK_DEBUG: '1' }, stdout: 'pipe', stderr: 'pipe' })
    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
    expect(out + err).toContain('probe')
    expect(out + err).not.toContain('sk-live-abcdef1234567890')
    expect(out + err).toContain('[REDACTED]')
  })
})
