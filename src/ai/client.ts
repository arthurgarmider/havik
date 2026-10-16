import { TypeSafeClient } from '@typesafe-ai/sdk'
import type { Judge } from './jev'

// The SDK reads TYPESAFE_API_KEY and TYPESAFE_BASE_URL itself. Its logging is off because it prints request
// bodies at debug level, and those bodies hold skill text.
export const createJudge = (): Judge => new TypeSafeClient({ logLevel: 'off', timeout: 20_000, retry: { maxRetries: 1 } })

// Where the skill text goes, for the notice printed before anything is sent.
export const jevHost = (): string => {
  try {
    return new URL(process.env['TYPESAFE_BASE_URL']?.trim() || 'https://api.typesafe.ai').host
  } catch {
    return 'the TypeSafe API'
  }
}
