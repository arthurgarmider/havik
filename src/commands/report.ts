import { execFile } from 'node:child_process'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { Command } from 'commander'
import { havikHome } from '../guard/policy'
import { renderReport } from '../report/html'
import { collect } from './collect'

// The program that opens a file in the browser, per platform.
const opener = (file: string): [string, string[]] =>
  process.platform === 'darwin' ? ['open', [file]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '""', file]] : ['xdg-open', [file]]

export const reportCommand = new Command('report')
  .description('The same as the default screen, as a page in your browser: the agents on this computer and what they did (a private local file)')
  .option('--no-open', 'write the page without opening it')
  .action(async (opts: { open: boolean }) => {
    const { overview, result, home } = await collect()
    const file = join(havikHome(), 'report.html')
    await mkdir(havikHome(), { recursive: true, mode: 0o700 })
    await writeFile(file, renderReport({ overview, result, now: Date.now(), home, span: '30 days' }), { mode: 0o600 })
    process.stdout.write(`havik report written to ${file}${opts.open ? '' : ' (open it in your browser)'}\n`)
    if (!opts.open) return
    const [program, args] = opener(file)
    execFile(program, args, (error) => { if (error) process.stdout.write(`Open it in your browser: ${file}\n`) })
  })
