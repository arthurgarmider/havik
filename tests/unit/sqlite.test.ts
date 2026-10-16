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

  it('says what went wrong instead of returning no rows', async () => {
    await withTree({}, async (dir) => {
      const missing = await sqliteQuery(join(dir, 'none.db'), 'select 1')
      expect(missing.ok).toBe(false)
      const noProgram = await sqliteQuery(join(dir, 'none.db'), 'select 1', { program: 'sqlite3-not-here' })
      expect(noProgram).toEqual({ ok: false, error: 'the sqlite3 program is not installed, so havik cannot read this database' })
    })
  })
})
