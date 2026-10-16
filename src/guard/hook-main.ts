import { homedir } from 'node:os'
import { loadSensitivityMap } from '../core/sensitivity'
import { handleEvent } from './engine'
import { eventsOfPayload } from './payload'
import { guardMap, loadGuardConfig } from './policy'
import { diskStore, loadSalt } from './session'

const MAX_STDIN = 8_000_000

// Time spent in havik's own checks, module loading excluded: what the budgets limit.
const started = performance.now()

const readStdin = (): Promise<string> =>
  new Promise(resolve => {
    let text = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk: string) => {
      text += chunk
      if (text.length > MAX_STDIN) {
        text = ''
        process.stdin.destroy()
        resolve('')
      }
    })
    process.stdin.on('end', () => resolve(text))
    process.stdin.on('error', () => resolve(''))
  })

const run = async (declared: string | undefined): Promise<string> => {
  const events = eventsOfPayload(await readStdin(), declared)
  if (events.length === 0) return ''
  const config = await loadGuardConfig()
  const options = {
    home: homedir(), config, map: guardMap(await loadSensitivityMap(), config), store: diskStore,
    // `ms` is the cost a user pays per tool call, Node start-up included.
    now: () => Date.now(), ms: () => Math.round(process.uptime() * 1000), spent: () => performance.now() - started,
    scanScripts: true, prune: true, salt: await loadSalt(),
  }
  let message = ''
  for (const event of events) message = (await handleEvent(event, options)) || message
  // Cursor's after-hooks take no answer: havik only records there.
  return declared === 'cursor' ? '' : message
}

// Detect-only: whatever happens, exit 0 and print nothing or exactly one JSON object.
// `declared` names the agent whose hook this is (--agent); without it the payload is Claude Code's.
export const hookMain = async (declared?: string): Promise<void> => {
  process.on('uncaughtException', () => { process.exitCode = 0 })
  process.on('unhandledRejection', () => { process.exitCode = 0 })
  // Gemini CLI parses stdout as JSON on exit 0, so an empty answer is the empty object there.
  const quiet = declared === 'gemini-cli' ? '{}' : ''
  const out = await run(declared).catch(() => '')
  if (out || quiet) process.stdout.write(out || quiet)
  process.exitCode = 0
}
