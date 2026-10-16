// Two bundles: the CLI, and the hook that Claude Code runs on every tool call.
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
