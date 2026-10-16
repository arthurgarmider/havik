// A named pipe: opening it for reading blocks forever, so a test that finishes proves nothing opened it.
export const mkfifo = async (path: string): Promise<void> => {
  const r = Bun.spawnSync(['mkfifo', path])
  if (r.exitCode !== 0) throw new Error(`mkfifo ${path} failed`)
}
