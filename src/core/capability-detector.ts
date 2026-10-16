import { trace } from './trace'
import { findFiles, readText } from './fs'
import { analyzeJsFile, isJsFile } from './js-analyzer'
import { loadSensitivityMap, type SensitivityMap } from './sensitivity'
import signaturesData from '../../data/capability-signatures.json'
import type { Capability, CapabilityResult, Result } from './types'

// JS/TS is read by the AST analyzer; Python is matched by anchored imports and boundary-checked calls.
type PythonSignatures = { imports?: string[]; calls?: string[] }
type Signatures = Record<Capability, { python?: PythonSignatures }>

const signatures = signaturesData as unknown as Signatures

export const CODE_GLOB = '**/*.{js,mjs,cjs,ts,mts,cts,jsx,tsx,py,sh,bash,zsh}'

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

const hasPythonImport = (source: string, mod: string): boolean =>
  new RegExp(`^\\s*(?:from\\s+${escapeRegExp(mod)}\\b|import\\s+(?:[\\w.]+\\s*,\\s*)*${escapeRegExp(mod)}\\b)`, 'm').test(source)

const hasPythonCall = (source: string, call: string): boolean =>
  new RegExp(`(?<![\\w.])${escapeRegExp(call)}`).test(source)

const pythonCapabilities = (source: string): Set<Capability> =>
  new Set(
    (Object.entries(signatures) as Array<[Capability, { python?: PythonSignatures }]>)
      .filter(([, sig]) => (sig.python?.imports ?? []).some(m => hasPythonImport(source, m)) || (sig.python?.calls ?? []).some(c => hasPythonCall(source, c)))
      .map(([cap]) => cap)
  )

export const capabilitiesOf = (file: string, source: string, map: SensitivityMap): ReadonlySet<Capability> =>
  isJsFile(file) ? analyzeJsFile(source, file, map).capabilities : file.endsWith('.py') ? pythonCapabilities(source) : new Set()

export const detectCapabilities = trace(
  'detectCapabilities',
  async (
    skillPath: string,
    declared: ReadonlySet<Capability> = new Set()
  ): Promise<Result<CapabilityResult>> => {
    try {
      const map = await loadSensitivityMap()
      const observed = new Set<Capability>()
      for (const file of await findFiles(CODE_GLOB, skillPath, { absolute: true })) {
        for (const cap of capabilitiesOf(file, await readText(file), map)) observed.add(cap)
      }
      const undeclared = new Set<Capability>()
      for (const cap of observed) {
        if (!declared.has(cap)) undeclared.add(cap)
      }
      return {
        ok: true,
        value: { observed, declared, undeclared }
      }
    } catch (error) {
      return { ok: false, error: `Failed to detect capabilities: ${error}` }
    }
  }
)
