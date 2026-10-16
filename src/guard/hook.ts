import { homedir } from 'node:os'
import { asRecord } from '../core/json'
import { loadSensitivityMap } from '../core/sensitivity'
import { handleEvent } from './engine'
import { guardMap, loadGuardConfig } from './policy'
import { diskStore, loadSalt } from './session'
import type { HookEvent } from './types'

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

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

const parseEvent = (raw: string): HookEvent | undefined => {
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return undefined
  }
  const e = asRecord(data)
  const [session_id, cwd, hook_event_name] = [str(e['session_id']), str(e['cwd']), str(e['hook_event_name'])]
  if (!session_id || !cwd || !hook_event_name) return undefined
  return {
    session_id, cwd, hook_event_name,
    permission_mode: str(e['permission_mode']), tool_name: str(e['tool_name']), tool_input: e['tool_input'], tool_response: e['tool_response'],
    tool_use_id: str(e['tool_use_id']), prompt: str(e['prompt']), last_assistant_message: str(e['last_assistant_message']), agent_id: str(e['agent_id']), agent_type: str(e['agent_type']), source: str(e['source']), model: str(e['model']),
  }
}

const run = async (): Promise<string> => {
  const event = parseEvent(await readStdin())
  if (!event) return ''
  const config = await loadGuardConfig()
  return handleEvent(event, {
    home: homedir(), config, map: guardMap(await loadSensitivityMap(), config), store: diskStore,
    // `ms` is the cost a user pays per tool call, Node start-up included.
    now: () => Date.now(), ms: () => Math.round(process.uptime() * 1000), spent: () => performance.now() - started,
    scanScripts: true, prune: true, salt: await loadSalt(),
  })
}

// Detect-only: whatever happens, exit 0 and print nothing or exactly one JSON object.
process.on('uncaughtException', () => { process.exitCode = 0 })
process.on('unhandledRejection', () => { process.exitCode = 0 })
run()
  .then(out => { if (out) process.stdout.write(out) }, () => undefined)
  .finally(() => { process.exitCode = 0 })
