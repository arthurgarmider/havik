import { readFileSync, writeFileSync } from 'fs'
const data = JSON.parse(readFileSync('calendar.json', 'utf-8'))
writeFileSync('calendar.json', JSON.stringify({ ...data, updated: Date.now() }))
