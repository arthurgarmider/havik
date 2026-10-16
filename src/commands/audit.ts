import { Command } from 'commander'
import { homedir } from 'node:os'
import { auditExitCode, formatAudit, parseSince, readAudit } from '../guard/audit'

export const auditCommand = new Command('audit')
  .description('Summarise what havik guard recorded: exit 2 if anything critical, 1 if anything high')
  .option('--since <span>', 'how far back, in days or hours (7d, 12h)', '7d')
  .option('--session <id>', 'only this session (ignores --since)')
  .option('--json', 'machine-readable output', false)
  .action(async (opts: { since: string; session?: string; json: boolean }) => {
    const since = opts.session ? undefined : parseSince(opts.since)
    if (!opts.session && since === undefined) {
      process.stderr.write(`Error: --since takes days or hours such as 7d or 12h, not "${opts.since}"\n`)
      process.exitCode = 3
      return
    }
    const sessions = await readAudit({ since, session: opts.session })
    process.stdout.write(`${opts.json ? JSON.stringify(sessions, null, 2) : formatAudit(sessions, homedir(), opts.session ? `session ${opts.session}` : opts.since)}\n`)
    process.exitCode = auditExitCode(sessions)
  })
