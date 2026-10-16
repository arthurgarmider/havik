import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'

// Two bundles: the CLI, and the hook that agents run on every tool call.
const builds = [
  { entrypoints: ['./src/index.ts'], naming: '[dir]/havik.js', banner: '#!/usr/bin/env node' },
  { entrypoints: ['./src/guard/hook.ts'], naming: 'guard.js', banner: '' },
]

for (const b of builds) {
  const result = await Bun.build({ ...b, outdir: './dist', target: 'node', format: 'esm', minify: false })
  if (!result.success) {
    for (const log of result.logs) console.error(log)
    process.exit(1)
  }
}
console.log('Build complete: dist/havik.js, dist/guard.js')

// --compile: standalone programs for people without Node, one per platform, with their SHA-256 sums.
// --compile=bun-darwin-arm64 builds one target only.
const compile = process.argv.find(a => a.startsWith('--compile'))
if (compile) {
  const all = ['bun-darwin-arm64', 'bun-darwin-x64', 'bun-linux-x64', 'bun-linux-arm64', 'bun-windows-x64']
  const targets = compile.includes('=') ? [compile.split('=')[1]] : all
  const sums: string[] = []
  for (const target of targets) {
    const out = `dist/bin/havik-${target.replace(/^bun-/, '')}${target.includes('windows') ? '.exe' : ''}`
    const r = Bun.spawnSync(['bun', 'build', '--compile', `--target=${target}`, './src/index.ts', '--outfile', out], { stdout: 'inherit', stderr: 'inherit' })
    if (r.exitCode !== 0) process.exit(1)
    sums.push(`${createHash('sha256').update(readFileSync(out)).digest('hex')}  ${out.replace('dist/bin/', '')}`)
  }
  writeFileSync('dist/bin/SHA256SUMS', `${sums.join('\n')}\n`)
  console.log(`Compiled: ${targets.join(', ')}`)
}
