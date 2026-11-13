import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { basename } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { Result } from './types'

const NOT_INSTALLED = 'the sqlite3 program is not installed, so havik cannot read this database'

// SQLite through the system sqlite3 program, read-only: a database an app is writing is never changed.
// Immutable skips the write-ahead log, where a running app keeps its newest rows; with a -wal file next to the database it is opened mode=ro instead.
// Node 20 and Bun have no built-in SQLite; /usr/bin/sqlite3 ships with macOS and most Linux systems.
export const sqliteQuery = (
  db: string, sql: string, opts: { timeoutMs?: number; maxBytes?: number; program?: string } = {},
): Promise<Result<Record<string, unknown>[]>> =>
  new Promise((resolve) => {
    const args = ['-readonly', '-json', `${pathToFileURL(db).href}?${existsSync(`${db}-wal`) ? 'mode=ro' : 'immutable=1'}`, sql]
    execFile(opts.program ?? 'sqlite3', args, { timeout: opts.timeoutMs ?? 10_000, maxBuffer: opts.maxBytes ?? 64 * 1024 * 1024 }, (error, stdout) => {
      if (error) {
        const missing = (error as NodeJS.ErrnoException).code === 'ENOENT'
        const why = error.killed ? `it took longer than ${Math.round((opts.timeoutMs ?? 10_000) / 1000)} s` : String(error.message).trim().split('\n').pop()
        return resolve({ ok: false, error: missing ? NOT_INSTALLED : `could not read ${basename(db)}: ${why}` })
      }
      try {
        resolve({ ok: true, value: stdout.trim() ? JSON.parse(stdout) : [] })
      } catch {
        resolve({ ok: false, error: `could not read ${basename(db)}: unexpected output` })
      }
    })
  })
