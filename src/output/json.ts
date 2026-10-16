import type { ScanResult } from '../core/types'
import { trace } from '../core/trace'

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Set) return [...value]
  return value
}

export const formatJson = trace(
  'formatJson',
  (result: ScanResult): string => JSON.stringify(result, replacer, 2)
)
