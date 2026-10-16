import { describe, it, expect } from 'bun:test'
import { mkfifo } from '../helpers/fifo'
import { utimes } from 'node:fs/promises'
import { join } from 'node:path'
import { newestMtime, pathExists } from '../../src/core/fs'
import { withTree } from '../helpers/tmp-tree'

describe('pathExists', () => {
  it('is true for files, directories and FIFOs, without opening them', async () => {
    await withTree({ 'a/b.txt': 'x' }, async (dir) => {
      await mkfifo(join(dir, 'pipe'))
      expect(await Promise.all([pathExists(join(dir, 'a')), pathExists(join(dir, 'a/b.txt')), pathExists(join(dir, 'pipe')), pathExists(join(dir, 'nope'))])).toEqual([true, true, true, false])
    })
  })
})

describe('newestMtime', () => {
  it('is the newest file time under a directory, within a depth', async () => {
    await withTree({ 'old.txt': 'x', 'sub/new.txt': 'y', 'sub/deeper/deep/deepest.txt': 'z' }, async (dir) => {
      await utimes(join(dir, 'old.txt'), new Date('2026-01-01'), new Date('2026-01-01'))
      await utimes(join(dir, 'sub/new.txt'), new Date('2026-05-01'), new Date('2026-05-01'))
      await utimes(join(dir, 'sub/deeper/deep/deepest.txt'), new Date('2026-09-01'), new Date('2026-09-01'))
      expect(new Date((await newestMtime(dir, { depth: 2 })) ?? 0).toISOString().slice(0, 10)).toBe('2026-05-01')
      expect(new Date((await newestMtime(dir, { depth: 4 })) ?? 0).toISOString().slice(0, 10)).toBe('2026-09-01')
    })
  })

  it('is undefined for a directory that is missing or empty', async () => {
    await withTree({}, async (dir) => {
      expect(await newestMtime(join(dir, 'none'))).toBeUndefined()
      expect(await newestMtime(dir)).toBeUndefined()
    })
  })
})
