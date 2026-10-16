import Ajv from 'ajv'
import * as yaml from 'js-yaml'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { trace } from './trace'
import { findFiles, readText } from './fs'
import { CORE_RULE_FILES } from './core-rules'
import { ruleSchema } from './rule-schema'
import type { Rule, Result } from './types'

const ajv = new Ajv({ allErrors: true })
const validate = ajv.compile(ruleSchema)

const MAX_FILE_SIZE = 1_000_000

export const validateRule = trace('validateRule', (data: unknown): Result<Rule> => {
  if (!validate(data)) {
    const errors = validate.errors?.map(e => `${e.instancePath} ${e.message}`).join('; ')
    return { ok: false, error: errors ?? 'Validation failed' }
  }
  return { ok: true, value: data as Rule }
})

// Every YAML document in one rule file, each validated against the schema.
const parseRules = (file: string, text: string): Result<Rule[]> => {
  const documents: unknown[] = []
  yaml.loadAll(text, (doc) => { documents.push(doc) }, { schema: yaml.DEFAULT_SCHEMA })
  const rules: Rule[] = []
  for (const parsed of documents) {
    const result = validateRule(parsed)
    if (!result.ok) return { ok: false, error: `Invalid rule in ${file}: ${result.error}` }
    rules.push(result.value)
  }
  return { ok: true, value: rules }
}

// The rules havik ships, from the copies built into the program.
export const loadCoreRules = (): Result<readonly Rule[]> => {
  try {
    const rules: Rule[] = []
    for (const { file, text } of [...CORE_RULE_FILES].sort((a, b) => a.file.localeCompare(b.file))) {
      const parsed = parseRules(file, text)
      if (!parsed.ok) return parsed
      rules.push(...parsed.value)
    }
    return { ok: true, value: rules }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export const loadRules = trace('loadRules', async (directory: string): Promise<Result<readonly Rule[]>> => {
  try {
    const files = await findFiles('**/*.{yaml,yml}', directory)

    if (files.length === 0) return { ok: true, value: [] }

    const results: Rule[] = []

    for (const file of files) {
      const path = join(directory, file)
      const { size } = await stat(path)

      if (size > MAX_FILE_SIZE) {
        return { ok: false, error: `File too large: ${file} (${size} bytes)` }
      }

      const parsed = parseRules(file, await readText(path))
      if (!parsed.ok) return parsed
      results.push(...parsed.value)
    }

    return { ok: true, value: results }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
})
