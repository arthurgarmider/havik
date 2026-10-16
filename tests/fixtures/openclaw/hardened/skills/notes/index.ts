import { readFileSync, writeFileSync } from 'fs'
const notes = JSON.parse(readFileSync('notes.json', 'utf-8'))
writeFileSync('notes.json', JSON.stringify({ ...notes, saved: Date.now() }))
