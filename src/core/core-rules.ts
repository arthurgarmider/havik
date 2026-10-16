import promptInjection from '../../rules/core/prompt-injection.yaml' with { type: 'text' }
import supplyChain from '../../rules/core/supply-chain.yaml' with { type: 'text' }

// The published rule files, built into the program so a standalone binary needs nothing next to it.
export const CORE_RULE_FILES: ReadonlyArray<{ readonly file: string; readonly text: string }> = [
  { file: 'prompt-injection.yaml', text: promptInjection },
  { file: 'supply-chain.yaml', text: supplyChain },
]
