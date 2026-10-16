import { Command, Option } from 'commander'
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { delimiter, join } from 'node:path'
import { MIN_CLAUDE_VERSION, TARGETS, binaryHookCommand, guardScript, guardStatus, hasGuard, hookCommand, installGuard, isStandalone, placeBinary, placeGuard, uninstallGuard, withGuardFor, type HookTarget } from '../guard/install'
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
  .description('Detect-only runtime guard for Claude Code, Codex and Gemini CLI: records and warns about sensitive data access, never blocks')
  .exitOverride()

const AGENTS = ['claude-code', 'codex', 'gemini-cli', 'cursor', 'all']
const agentOption = () => new Option('--agent <id>', 'which agent: claude-code, codex, gemini-cli, cursor (records only), or all that are set up here').choices(AGENTS).default('claude-code')

// `all` means every agent with a settings folder on this computer.
const onPath = (bin: string): boolean => (process.env.PATH ?? '').split(delimiter).some(dir => dir && existsSync(join(dir, bin)))
const isSetUp = (t: HookTarget): boolean => t.setUp.paths.some(p => existsSync(join(homedir(), p))) || (t.setUp.bins ?? []).some(onPath)
const targetsFor = (agent: string): HookTarget[] => (agent === 'all' ? Object.values(TARGETS).filter(isSetUp) : [TARGETS[agent]])

// --project applies to Claude Code, whose project settings live in ./.claude.
const fileFor = (t: HookTarget, project: boolean): string => (t.agent === 'claude-code' ? settingsFile(project) : t.file(homedir()))
const agentFlag = (t: HookTarget): string | undefined => (t.agent === 'claude-code' ? undefined : t.agent)
const commandFor = (t: HookTarget, script: string): string => (isStandalone() ? binaryHookCommand(script, agentFlag(t)) : hookCommand(process.execPath, script, agentFlag(t)))

guardCommand.command('install')
  .description('Add the guard hooks to an agent\'s settings: Claude Code (~/.claude/settings.json), Codex or Gemini CLI (a backup is written first)')
  .option('--project', 'Install into ./.claude/settings.json instead (Claude Code)', false)
  .option('--print', 'Only print the hooks JSON, for managed settings or review', false)
  .addOption(agentOption())
  .action(async (opts: { project: boolean; print: boolean; agent: string }) => {
    const script = isStandalone() ? process.execPath : guardScript()
    if (!existsSync(script)) return fail(`${script} is missing; build havik first (bun run build)`)
    const targets = targetsFor(opts.agent)
    if (opts.print) {
      if (targets.length !== 1) return fail('--print shows one agent\'s hooks: name it with --agent')
      process.stdout.write(`${JSON.stringify(withGuardFor(targets[0], {}, commandFor(targets[0], script)), null, 2)}\n`)
      return
    }
    if (targets.length === 0) return fail('no agent with hooks havik can install into is set up here')
    const placed = await (isStandalone() ? placeBinary(havikHome()) : placeGuard(script, havikHome())).catch((e: unknown) => e instanceof Error ? e : new Error(String(e)))
    if (placed instanceof Error) return fail(`could not copy the guard into ${havikHome()}: ${placed.message}`)
    const lines: string[] = []
    for (const t of targets) {
      const file = fileFor(t, opts.project)
      const result = await installGuard(file, commandFor(t, placed), new Date(), t)
      if (!result.ok) return fail(result.error)
      lines.push(`havik guard installed for ${t.name} in ${file}${result.value.backup ? ` (backup: ${result.value.backup})` : ''}.`, ...(t.note ? [t.note] : []))
    }
    process.stdout.write(`${[...lines, `It records to ${join(havikHome(), 'audit')} and warns in the session; it never blocks. Read it with: havik audit`, 'Re-run this command after upgrading havik or Node.'].join('\n')}\n`)
  })

guardCommand.command('uninstall')
  .description('Remove the guard hooks')
  .option('--project', 'Remove from ./.claude/settings.json instead (Claude Code)', false)
  .addOption(agentOption())
  .action(async (opts: { project: boolean; agent: string }) => {
    for (const t of targetsFor(opts.agent)) {
      const file = fileFor(t, opts.project)
      const result = await uninstallGuard(file)
      if (!result.ok) return fail(result.error)
      process.stdout.write(result.value.removed ? `havik guard removed from ${file}.\n` : `havik guard was not installed in ${file}.\n`)
    }
  })

guardCommand.command('status')
  .description('Where the guard is installed and what could silence it; exit 0 when it will run, 3 otherwise')
  .addOption(agentOption())
  .action(async (opts: { agent: string }) => {
    const others = targetsFor(opts.agent).filter(t => t.agent !== 'claude-code')
    if (opts.agent !== 'all' && others.length > 0) {
      const t = others[0]
      const installed = await hasGuard(t.file(homedir()))
      process.stdout.write(`${t.name}: ${installed ? `installed in ${t.file(homedir())}` : `not installed (havik guard install --agent ${t.agent})`}\n`)
      process.exitCode = installed ? 0 : 3
      return
    }
    for (const t of others) {
      const installed = await hasGuard(t.file(homedir()))
      process.stdout.write(`${t.name}: ${installed ? `installed in ${t.file(homedir())}` : `not installed (havik guard install --agent ${t.agent})`}\n`)
    }
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

