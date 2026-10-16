import { lstat, open, readdir, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { glob } from 'tinyglobby'

// Relative to the scan root; never worth scanning and a common source of noise or loops.
export const VENDORED = ['**/node_modules/**', '**/.git/**']
const IGNORE = [...VENDORED, '**/dist/**', 'Library/**', '.Trash/**']
const MAX_DEPTH = 8

export const readText = (path: string): Promise<string> => readFile(path, 'utf8')

export const readTextOrNull = (path: string): Promise<string | null> => readText(path).catch(() => null)

// Reads at most maxBytes from a regular file; anything else (directory, FIFO, device) reads as empty.
export const readTextHead = async (path: string, maxBytes: number): Promise<{ text: string; truncated: boolean }> => {
  const info = await stat(path)
  if (!info.isFile()) return { text: '', truncated: false }
  const handle = await open(path, 'r')
  try {
    const buffer = Buffer.alloc(Math.min(info.size, maxBytes))
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
    return { text: buffer.toString('utf8', 0, bytesRead), truncated: info.size > maxBytes }
  } finally {
    await handle.close()
  }
}

// A symlink, even a dangling one. havik never follows links to files it was not pointed at.
export const isSymlink = (path: string): Promise<boolean> => lstat(path).then((s) => s.isSymbolicLink(), () => false)

export const fileExists = (path: string): Promise<boolean> => stat(path).then((s) => s.isFile(), () => false)

// Anything at this path (file, directory, pipe), found with stat alone: nothing is opened.
export const pathExists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false)

// The newest file time under a directory: files directly inside are depth 1. Links are not followed; at most maxFiles entries are looked at.
export const newestMtime = async (dir: string, opts: { depth?: number; maxFiles?: number } = {}): Promise<number | undefined> => {
  const depth = opts.depth ?? 4
  let budget = opts.maxFiles ?? 5_000
  let newest: number | undefined
  const walk = async (at: string, level: number): Promise<void> => {
    const entries = await readdir(at, { withFileTypes: true }).catch(() => [])
    for (const entry of entries) {
      if (budget-- <= 0) return
      const path = join(at, entry.name)
      if (entry.isDirectory()) {
        if (level < depth) await walk(path, level + 1)
      } else if (entry.isFile()) {
        const info = await lstat(path).catch(() => null)
        if (info && (newest === undefined || info.mtimeMs > newest)) newest = info.mtimeMs
      }
    }
  }
  await walk(dir, 1)
  return newest
}

export const findFiles = async (
  pattern: string,
  cwd: string,
  opts: { dot?: boolean; absolute?: boolean; deep?: number; ignore?: readonly string[] } = {},
): Promise<string[]> =>
  (await glob(pattern, {
    cwd,
    dot: opts.dot ?? false,
    absolute: opts.absolute ?? false,
    ignore: [...(opts.ignore ?? IGNORE)],
    deep: opts.deep ?? MAX_DEPTH,
    followSymbolicLinks: false,
    onlyFiles: true,
  })).sort()
