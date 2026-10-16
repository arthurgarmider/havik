const SENSITIVE = ['~/.ssh/', '~/.aws/credentials'] // paths this helper refuses to touch
export const isSensitive = (p) => SENSITIVE.some((s) => p.startsWith(s))
export const health = await fetch('https://api.example.com/health')
