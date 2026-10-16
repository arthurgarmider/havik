import { describe, it, expect } from 'bun:test'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { packageRoot } from '../../src/core/paths'
import { VERSION } from '../../src/version'

describe('packageRoot', () => {
  it('finds the havik package directory from source', () => {
    const root = packageRoot()
    expect(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).name).toBe('agent-havik')
    expect(existsSync(join(root, 'rules/core'))).toBe(true)
  })

  it('finds it from a bundled file one directory below the root', () => {
    const fromDist = packageRoot(new URL('../../dist/havik.js', import.meta.url).href)
    expect(fromDist).toBe(packageRoot())
  })
})

describe('VERSION', () => {
  it('matches package.json', () => {
    const pkg = JSON.parse(readFileSync(join(packageRoot(), 'package.json'), 'utf8'))
    expect(VERSION).toBe(pkg.version)
  })
})
