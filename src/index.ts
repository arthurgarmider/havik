import { Command, CommanderError } from 'commander'
import { scanCommand } from './commands/scan'
import { guardCommand } from './commands/guard'
import { auditCommand } from './commands/audit'
import { agentsCommand } from './commands/agents'
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

// A mistyped option is "could not scan" (3), never a clean result; --help and --version stay 0.
try {
  // No arguments at all: the one-screen summary of what Claude Code touched lately.
  if (process.argv.length <= 2) await touchedAction()
  else program.parse()
} catch (error) {
  if (!(error instanceof CommanderError)) throw error
  process.exitCode = error.exitCode === 0 ? 0 : 3
}
