// Builds a small SQLite database with the system sqlite3 program, as the readers use.
export const makeDb = (path: string, sql: string): void => {
  const r = Bun.spawnSync(['sqlite3', path, sql])
  if (r.exitCode !== 0) throw new Error(`sqlite3 failed: ${r.stderr.toString()}`)
}
