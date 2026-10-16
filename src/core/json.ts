// Configs from a scanned tree are untrusted: a wrong shape must read as empty, not crash the scan.
export const asRecord = (value: unknown): Record<string, any> =>
  value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, any>) : {}

export const asArray = (value: unknown): any[] => (Array.isArray(value) ? value : [])

// Frontmatter lists arrive as "a, b" or as a YAML list.
export const toList = (value: unknown): string[] =>
  (Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : []).map(item => String(item).trim()).filter(Boolean)
