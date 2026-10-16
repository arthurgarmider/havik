export const ruleSchema = {
  type: 'object',
  required: ['id', 'type', 'severity', 'confidence', 'owasp', 'frameworks', 'description', 'match'],
  additionalProperties: false,
  properties: {
    id: { type: 'string', minLength: 1 },
    type: { type: 'string', enum: ['capability_mismatch', 'pattern'] },
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    owasp: { type: 'string', pattern: '^ASI\\d{2}$' },
    frameworks: { type: 'array', items: { type: 'string' }, minItems: 1 },
    description: { type: 'string', minLength: 1 },
    match: { type: 'object' },
    metadata: {
      type: 'object',
      required: ['author', 'created'],
      additionalProperties: false,
      properties: {
        author: { type: 'string' },
        created: { type: 'string' },
        references: { type: 'array', items: { type: 'string' } },
      },
    },
  },
} as const
