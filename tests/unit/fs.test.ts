import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { findFiles, isSymlink, readText, readTextHead, readTextOrNull } from '../../src/core/fs'

let root: string
const put = async (rel: string, body = 'x') => {
  await mkdir(join(root, rel, '..'), { recursive: true })
  await writeFile(join(root, rel), body)
}

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'havik-fs-'))
  await put('b.js')
  await put('a.js')
  await put('sub/c.py')
  await put('.hidden.js')
  await put('.env')
  await put('node_modules/dep/index.js')
  await put('.git/hooks/x.js')
  await put('dist/out.js')
  await mkdir(join(root, 'empty-dir'))
  await symlink(root, join(root, 'loop'))
})
afterAll(() => rm(root, { recursive: true, force: true }))

describe('findFiles', () => {
  it('returns sorted relative file paths, never directories', async () => {
    expect(await findFiles('**/*.{js,py}', root)).toEqual(['a.js', 'b.js', 'sub/c.py'])
  })

  it('skips dotfiles unless asked', async () => {
    expect(await findFiles('*.js', root)).not.toContain('.hidden.js')
    expect(await findFiles('*.js', root, { dot: true })).toContain('.hidden.js')
    expect(await findFiles('{.env,.env.*}', root, { dot: true })).toEqual(['.env'])
  })

  it('never descends into node_modules, .git, dist or symlink loops', async () => {
    const all = await findFiles('**/*', root, { dot: true })
    expect(all.filter((f) => /node_modules|\.git\/|^dist\/|^loop/.test(f))).toEqual([])
  })

  it('returns absolute paths on request', async () => {
    expect(await findFiles('*.js', root, { absolute: true })).toEqual([join(root, 'a.js'), join(root, 'b.js')])
  })

  it('limits how many directory levels it descends', async () => {
    await put('d1/d2/d3/deep.js')
    expect(await findFiles('**/deep.js', root, { deep: 2 })).toEqual([])
    expect(await findFiles('**/deep.js', root, { deep: 3 })).toEqual(['d1/d2/d3/deep.js'])
  })

  it('returns nothing for a directory that does not exist', async () => {
    expect(await findFiles('**/*', join(root, 'nope'))).toEqual([])
  })
})

describe('readText / readTextOrNull', () => {
  it('reads utf8 text', async () => {
    await put('t.txt', 'héllo')
    expect(await readText(join(root, 't.txt'))).toBe('héllo')
  })

  it('readTextOrNull is null for a missing file or a directory', async () => {
    expect(await readTextOrNull(join(root, 'missing.txt'))).toBeNull()
    expect(await readTextOrNull(join(root, 'sub'))).toBeNull()
  })
})

describe('readTextHead', () => {
  it('reads a small file whole and flags a bigger one as truncated', async () => {
    await put('small.txt', 'hello')
    await put('big.txt', 'abcdefghij')
    expect(await readTextHead(join(root, 'small.txt'), 100)).toEqual({ text: 'hello', truncated: false })
    expect(await readTextHead(join(root, 'big.txt'), 4)).toEqual({ text: 'abcd', truncated: true })
  })

  it('reads a directory as empty instead of failing', async () => {
    expect(await readTextHead(join(root, 'sub'), 100)).toEqual({ text: '', truncated: false })
  })
})

describe('isSymlink', () => {
  it('is true for a link, even a dangling one, and false for files, directories and missing paths', async () => {
    await symlink(join(root, 'nowhere'), join(root, 'dangling'))
    expect(await isSymlink(join(root, 'loop'))).toBe(true)
    expect(await isSymlink(join(root, 'dangling'))).toBe(true)
    expect(await isSymlink(join(root, 'a.js'))).toBe(false)
    expect(await isSymlink(join(root, 'sub'))).toBe(false)
    expect(await isSymlink(join(root, 'missing'))).toBe(false)
  })
})
