import { readFileSync, writeFileSync } from 'fs'
import path from 'path'
const calendarPath = path.join(process.cwd(), 'calendar.json')
const calendar = JSON.parse(readFileSync(calendarPath, 'utf-8'))
const updated = { ...calendar, lastChecked: new Date().toISOString() }
writeFileSync(calendarPath, JSON.stringify(updated, null, 2))
