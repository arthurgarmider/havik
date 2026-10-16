import { lstat, open, readFile, stat } from 'node:fs/promises'
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
