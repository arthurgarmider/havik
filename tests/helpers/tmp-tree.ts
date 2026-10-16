import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

// Builds a throwaway directory tree, hands it to `run`, and always removes it.
export async function withTree<T>(files: Record<string, string>, run: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'havik-tree-'))
  try {
    for (const [rel, body] of Object.entries(files)) {
      await mkdir(dirname(join(dir, rel)), { recursive: true })
      await writeFile(join(dir, rel), body)
    }
    return await run(dir)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}
