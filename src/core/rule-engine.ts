import Ajv from 'ajv'
import * as yaml from 'js-yaml'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { trace } from './trace'
import { findFiles, readText } from './fs'
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

      const text = await readText(path)
      const documents: unknown[] = []
      yaml.loadAll(text, (doc) => { documents.push(doc) }, { schema: yaml.DEFAULT_SCHEMA })

      for (const parsed of documents) {
        const result = validateRule(parsed)
        if (!result.ok) return { ok: false, error: `Invalid rule in ${file}: ${result.error}` }
        results.push(result.value)
      }
    }

    return { ok: true, value: results }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
})
