import { Command, CommanderError } from 'commander'
import { scanCommand } from './commands/scan'
import { guardCommand } from './commands/guard'
import { auditCommand } from './commands/audit'
import { agentsCommand } from './commands/agents'
import { reportCommand } from './commands/report'
import { hookMain } from './guard/hook-main'
import { touchedAction } from './commands/touched'
import { VERSION } from './version'

const program = new Command()
  .name('havik')
  .description('The AI agents on your computer, and what they touched; plus a scanner for agent skills and tool servers')
  .version(VERSION)

program.exitOverride()
program.addCommand(scanCommand.exitOverride())
program.addCommand(guardCommand)
program.addCommand(auditCommand.exitOverride())
program.addCommand(agentsCommand.exitOverride())
program.addCommand(reportCommand.exitOverride())
// The guard itself, for hooks installed by the standalone program; not for people.
const hook = new Command('hook').option('--agent <id>').allowUnknownOption().allowExcessArguments()
  .configureOutput({ writeErr: () => undefined }).exitOverride().action((opts: { agent?: string }) => hookMain(opts.agent))
program.addCommand(hook, { hidden: true })

// A mistyped option is "could not scan" (3), never a clean result; --help and --version stay 0.
try {
  // No arguments at all: the one-screen summary of what Claude Code touched lately.
  if (process.argv.length <= 2) await touchedAction()
  else program.parse()
} catch (error) {
  if (!(error instanceof CommanderError)) throw error
  // The guard never fails a session, whatever its command line says.
  process.exitCode = error.exitCode === 0 || process.argv[2] === 'hook' ? 0 : 3
}
