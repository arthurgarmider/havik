import { basename } from 'node:path'
import { asRecord } from '../core/json'

// Shared by the history readers: each agent's tool names and arguments, said in havik's vocabulary
// (Bash, Read, Write, Edit, Grep, Glob, WebFetch, Patch, mcp__server__tool) so the detectors need no change.
export interface Translated { readonly tool_name: string; readonly tool_input: unknown; readonly cwd?: string }
// A translation is a tool havik understands, null for one that touches nothing, undefined for one it does not know.
export type Translation = Translated | null | undefined

export const parseArgs = (raw: unknown): Record<string, any> => {
  if (typeof raw !== 'string') return asRecord(raw)
  try {
    return asRecord(JSON.parse(raw))
  } catch {
    return {}
  }
}

export const pick = (args: Record<string, any>, keys: readonly string[]): string | undefined => {
  for (const key of keys) if (typeof args[key] === 'string') return args[key]
  return undefined
}

// A command as one line of shell: `["bash", "-lc", "cat a"]` is `cat a`.
export const shellText = (command: unknown): string => {
  if (!Array.isArray(command)) return typeof command === 'string' ? command : ''
  const words = command.map(String)
  if (words.length >= 3 && /^(?:ba|z|da)?sh$/.test(basename(words[0])) && /^-l?c$/.test(words[1])) return words[2]
  return words.join(' ')
}
