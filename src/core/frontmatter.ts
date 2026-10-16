import * as yaml from 'js-yaml'
import { asRecord } from './json'

// Splits a SKILL.md or agent file into its YAML header and body. The YAML parse throws when the header is invalid.
export const splitFrontmatter = (content: string): { data: Record<string, unknown>; body: string } => {
  const match = content.match(/^---\n([\s\S]*?)\n---\n?/)
  return match ? { data: asRecord(yaml.load(match[1])), body: content.slice(match[0].length) } : { data: {}, body: content }
}
