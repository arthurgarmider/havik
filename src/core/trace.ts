import { redactSecrets } from './redact'

const DEBUG = process.env.HAVIK_DEBUG === '1'

// Debug lines go to stderr so they never end up inside --format json output.
const log = (line: string): void => void process.stderr.write(`${line}\n`)

export function trace<TArgs extends unknown[], TReturn>(
  name: string,
  fn: (...args: TArgs) => TReturn
): (...args: TArgs) => TReturn {
  if (!DEBUG) return fn
  return (...args: TArgs): TReturn => {
    const start = performance.now()
    log(`→ ${name}(${redactSecrets(args.map(a => JSON.stringify(a)).join(', ')).slice(0, 2000)})`)
    try {
      const result = fn(...args)
      if (result instanceof Promise) {
        return result.then(r => {
          log(`← ${name} [${(performance.now() - start).toFixed(1)}ms]`)
          return r
        }) as TReturn
      }
      log(`← ${name} [${(performance.now() - start).toFixed(1)}ms]`)
      return result
    } catch (err) {
      log(`✕ ${name} threw [${(performance.now() - start).toFixed(1)}ms]`)
      throw err
    }
  }
}
