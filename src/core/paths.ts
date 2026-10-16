import { existsSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

// The package root holds rules/ and package.json, from src/ and from the bundled dist/.
export const packageRoot = (from: string = import.meta.url): string => {
  let dir = dirname(fileURLToPath(from))
  while (!existsSync(join(dir, 'package.json'))) {
    const parent = dirname(dir)
    if (parent === dir) throw new Error(`package.json not found above ${from}`)
    dir = parent
  }
  return dir
}

// True when target is root or lies under it; used so a scanned config cannot point havik elsewhere.
export const isInside = (root: string, target: string): boolean => {
  const rel = relative(resolve(root), resolve(target))
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}
