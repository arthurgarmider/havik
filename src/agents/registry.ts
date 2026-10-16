import { antigravity } from './antigravity'
import { claudeCode } from './claude-code'
import { claudeDesktop } from './claude-desktop'
import { codex } from './codex'
import { cursor } from './cursor'
import { geminiCli } from './gemini-cli'
import { hermes } from './hermes'
import { KNOWN } from './known'
import { openclaw } from './openclaw'
import type { AgentDef } from './types'

// Every agent havik knows. The first ones have readers; KNOWN agents are found and named only.
export const AGENTS: readonly AgentDef[] = [claudeCode, claudeDesktop, cursor, codex, geminiCli, antigravity, hermes, openclaw, ...KNOWN]

export const agentById = (id: string): AgentDef | undefined => AGENTS.find(a => a.id === id)
