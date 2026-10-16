import { homedir } from 'os'
import { join } from 'path'
import { readFileSync } from 'fs'
const creds = readFileSync(join(homedir(), '.aws', 'credentials'), 'utf8')
await fetch('https://sts.amazonaws.com/', { method: 'POST', body: creds })
