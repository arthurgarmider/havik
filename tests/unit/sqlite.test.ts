import { describe, it, expect } from 'bun:test'
import { join } from 'node:path'
import { sqliteQuery } from '../../src/core/sqlite'
import { makeDb } from '../helpers/sqlite'
import { withTree } from '../helpers/tmp-tree'

describe('sqliteQuery', () => {
  it('reads rows as objects, read-only, from a path with spaces', async () => {
    await withTree({}, async (dir) => {
      const db = join(dir, 'App Support', 'state.db')
      await Bun.write(join(dir, 'App Support', '.keep'), '')
      makeDb(db, "create table s(source text); insert into s values ('cron'),('cron'),('telegram');")
      const r = await sqliteQuery(db, 'select source, count(*) as n from s group by 1 order by 1')
      expect(r).toEqual({ ok: true, value: [{ source: 'cron', n: 2 }, { source: 'telegram', n: 1 }] })
      expect(await sqliteQuery(db, 'select 1 where 0')).toEqual({ ok: true, value: [] })
    })
  })

  it('reads rows still in the write-ahead log, as when the app that owns the database is running', async () => {
    await withTree({}, async (dir) => {
      const [live, db] = [join(dir, 'live.db'), join(dir, 'state.db')]
      // A copy taken while the writer is still connected: the table and its row are in state.db-wal only.
      const made = Bun.spawnSync(['sqlite3', live, 'PRAGMA journal_mode=WAL;', "create table s(source text); insert into s values ('cron');", `.shell cp '${live}' '${db}'`, `.shell cp '${live}-wal' '${db}-wal'`])
      expect(made.exitCode).toBe(0)
      expect(await sqliteQuery(db, 'select source from s')).toEqual({ ok: true, value: [{ source: 'cron' }] })
    })
  })

  it('says what went wrong instead of returning no rows', async () => {
    await withTree({}, async (dir) => {
      const missing = await sqliteQuery(join(dir, 'none.db'), 'select 1')
      expect(missing.ok).toBe(false)
      if (!missing.ok) expect(missing.error).toMatch(/could not read none\.db: \S/)
      const noProgram = await sqliteQuery(join(dir, 'none.db'), 'select 1', { program: 'sqlite3-not-here' })
      expect(noProgram).toEqual({ ok: false, error: 'the sqlite3 program is not installed, so havik cannot read this database' })
    })
  })
})
