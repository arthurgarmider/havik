import { Command } from 'commander'
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { MIN_CLAUDE_VERSION, guardScript, guardStatus, hookCommand, installGuard, uninstallGuard, withGuard } from '../guard/install'
import { guardMap, havikHome, loadGuardConfig } from '../guard/policy'
import { formatReplay, replaySessions } from '../guard/replay'
import { auditExitCode, parseSince } from '../guard/audit'
import { loadSensitivityMap } from '../core/sensitivity'

const settingsFile = (project: boolean): string =>
  project ? join(process.cwd(), '.claude', 'settings.json') : join(homedir(), '.claude', 'settings.json')

const fail = (message: string): void => {
  process.stderr.write(`Error: ${message}\n`)
  process.exitCode = 3
}

const claudeVersion = (): Promise<string | undefined> =>
  new Promise(resolve => execFile('claude', ['--version'], { timeout: 5_000 }, (error, stdout) => resolve(error ? undefined : stdout.match(/\d+\.\d+\.\d+/)?.[0])))

// exitOverride first, so the subcommands below inherit it: a usage mistake exits 3 like every other havik command.
export const guardCommand = new Command('guard')
  .description('Detect-only runtime guard for Claude Code: records and warns about sensitive data access, never blocks')
  .exitOverride()

guardCommand.command('install')
  .description('Add the guard hooks to ~/.claude/settings.json (a backup is written first)')
  .option('--project', 'Install into ./.claude/settings.json instead', false)
  .option('--print', 'Only print the hooks JSON, for managed settings or review', false)
  .action(async (opts: { project: boolean; print: boolean }) => {
    const script = guardScript()
    if (!existsSync(script)) return fail(`${script} is missing; build havik first (bun run build)`)
    const command = hookCommand(process.execPath, script)
    if (opts.print) {
      process.stdout.write(`${JSON.stringify(withGuard({}, command), null, 2)}\n`)
      return
    }
    const file = settingsFile(opts.project)
    const result = await installGuard(file, command)
    if (!result.ok) return fail(result.error)
    const backup = result.value.backup ? ` (backup: ${result.value.backup})` : ''
    process.stdout.write(`havik guard installed in ${file}${backup}.\nIt records to ${join(havikHome(), 'audit')} and warns in the session; it never blocks. Read it with: havik audit\nRe-run this command after upgrading havik or Node.\n`)
  })

guardCommand.command('uninstall')
  .description('Remove the guard hooks')
  .option('--project', 'Remove from ./.claude/settings.json instead', false)
  .action(async (opts: { project: boolean }) => {
    const file = settingsFile(opts.project)
    const result = await uninstallGuard(file)
    if (!result.ok) return fail(result.error)
    process.stdout.write(result.value.removed ? `havik guard removed from ${file}.\n` : `havik guard was not installed in ${file}.\n`)
  })

guardCommand.command('status')
  .description('Where the guard is installed and what could silence it; exit 0 when it will run, 3 otherwise')
  .action(async () => {
    const s = await guardStatus(process.cwd(), homedir(), await claudeVersion())
    const lines = [
      s.installedIn.length > 0 ? `installed in: ${s.installedIn.join(', ')}` : 'not installed (havik guard install)',
      ...s.missingScripts.map(p => `stale: the hook points at ${p}, which does not exist; re-run havik guard install`),
      ...s.disabledBy.map(p => `silenced: ${p} sets disableAllHooks, so no user hook runs here`),
      s.claudeVersion ? `Claude Code ${s.claudeVersion}${s.versionOk ? '' : `, older than ${MIN_CLAUDE_VERSION}, which the guard was verified on`}` : 'Claude Code: version unknown (claude --version failed)',
      `sandbox: ${s.sandbox ? 'on' : 'off'}`,
    ]
    process.stdout.write(`${lines.join('\n')}\n`)
    const healthy = s.installedIn.length > 0 && s.missingScripts.length === 0 && s.disabledBy.length === 0 && s.versionOk !== false
    process.exitCode = healthy ? 0 : 3
  })

guardCommand.command('replay')
  .description('What the guard would have said about your past Claude Code sessions, from ~/.claude/projects (nothing is installed or sent)')
  .option('--since <span>', 'how far back, in days or hours (30d, 12h)', '30d')
  .option('--dir <path>', 'the transcripts directory', join(homedir(), '.claude', 'projects'))
  .option('--all', 'list every session, not only those that would have warned', false)
  .option('--json', 'machine-readable output', false)
  .action(async (opts: { since: string; dir: string; all: boolean; json: boolean }) => {
    const since = parseSince(opts.since)
    if (since === undefined) return fail(`--since takes days or hours such as 30d or 12h, not "${opts.since}"`)
    const config = await loadGuardConfig()
    const result = await replaySessions({ projectsDir: opts.dir, home: homedir(), config, map: guardMap(await loadSensitivityMap(), config), since })
    process.stdout.write(`${opts.json ? JSON.stringify(result, null, 2) : formatReplay(result, opts.dir, opts.since, homedir(), opts.all)}\n`)
    process.exitCode = auditExitCode(result.summaries)
  })

