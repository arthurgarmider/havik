import { parse, type ParserPlugin } from '@babel/parser'
import { classifyPath, type SensitivityMap } from './sensitivity'
import { hostOf, isLocalHost, scanLines, withoutProcessEnv, type Sink, type Source } from './exfil-patterns'
import { redactSecrets } from './redact'
import type { Capability } from './types'

// Reads JS/TS the way the runtime would: follows imports, requires, destructuring and aliases,
// folds string tricks ('child_' + 'process'), and reports capabilities, secret sources, network
// sinks and names assembled at runtime. Anything it cannot parse is reported, never guessed.
type N = { type: string; loc?: { start: { line: number } }; [key: string]: any }
type Ref = { readonly name: string; readonly folded: boolean }
type Folded = { readonly value: string; readonly literal: boolean }

export interface Obfuscation { readonly line: number; readonly name: string }
export interface JsEvidence {
  readonly parsed: boolean
  readonly capabilities: ReadonlySet<Capability>
  readonly sources: readonly Source[]
  readonly sinks: readonly Sink[]
  readonly obfuscated: readonly Obfuscation[]
}

const MAX_BYTES = 1_000_000
const MAX_DEPTH = 64 // expression nesting plus alias hops, so alias cycles end
const MAX_ALIAS_HOPS = 8
const MAX_FOLD_LENGTH = 20_000 // a doubling alias chain must not build a multi-gigabyte string
const MAX_BINDINGS = 16 // per name: the first ones and the latest; a file that rebinds one name thousands of times is not analysed per binding
const MAX_STEPS = 3_000_000 // total work per file; a hostile file falls back to line patterns instead of hanging
const UNPARSED: JsEvidence = { parsed: false, capabilities: new Set(), sources: [], sinks: [], obfuscated: [] }

export const isJsFile = (file: string): boolean => /\.(?:[cm]?[jt]s|[jt]sx)$/.test(file) && !file.endsWith('.d.ts')

// Names are "mod:<module>[.member]" for imports and "g:<name>[.member]" for globals.
const fsFns = (names: string[]) => names.flatMap(n => [`mod:fs.${n}`, `mod:fs.promises.${n}`])
const caps = (keys: string[], cap: Capability): Array<[string, Capability]> => keys.map(k => [k, cap])
const FS_CONTENT = ['readFile', 'readFileSync', 'createReadStream']
const CALL_CAP = new Map<string, Capability>([
  ...caps(fsFns([...FS_CONTENT, 'readdir', 'readdirSync']), 'filesystem.read'),
  ...caps(fsFns(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'unlink', 'unlinkSync', 'mkdir', 'mkdirSync', 'rm', 'rmSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync']), 'filesystem.write'),
  ...caps(['g:fetch', 'g:XMLHttpRequest', 'g:WebSocket', 'g:EventSource'], 'network'),
  ...caps(['g:Bun.file', 'g:Deno.readFile', 'g:Deno.readTextFile'], 'filesystem.read'),
  ...caps(['g:Bun.write', 'g:Deno.writeFile', 'g:Deno.writeTextFile'], 'filesystem.write'),
])
const MODULE_CAP = new Map<string, Capability>([
  ...caps(['node-fetch', 'axios', 'got', 'undici', 'ky', 'superagent', 'ws', 'socket.io-client', 'http', 'https', 'http2', 'net', 'tls', 'dgram', 'dns'], 'network'),
  ...caps(['child_process', 'execa', 'zx', 'shelljs', 'cross-spawn'], 'shell'),
])
const SHELL_CALLS = new Set([
  ...['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'].map(f => `mod:child_process.${f}`),
  'g:Bun.spawn', 'g:Bun.spawnSync', 'g:Bun.$', 'g:Deno.run', 'g:Deno.Command', 'mod:bun.$', 'mod:bun.spawn', 'mod:zx.$',
  'mod:execa', 'mod:execa.execa', 'mod:execa.execaCommand', 'mod:shelljs.exec', 'mod:cross-spawn',
])
const READ_CONTENT = new Set([...fsFns(FS_CONTENT), 'g:Bun.file', 'g:Deno.readFile', 'g:Deno.readTextFile'])
const SEND_ALWAYS = /^mod:(?:axios|got|ky|undici)\.(?:post|put|patch)$/
const SEND_WITH_OPTIONS = new Set(['g:fetch', 'mod:http.request', 'mod:https.request', 'mod:axios', 'mod:axios.request', 'mod:got', 'mod:node-fetch', 'mod:undici.fetch', 'mod:undici.request'])
const BODY_KEYS = new Set(['body', 'data', 'json'])
// Calls that copy their argument into the data being sent; anything else (cleanEnv(process.env)) just reads it.
const SERIALIZERS = new Set([
  ...['stringify', 'entries', 'keys', 'values', 'assign', 'fromEntries'].map(f => `g:${f === 'stringify' ? 'JSON' : 'Object'}.${f}`),
  'g:Buffer.from', 'g:btoa', 'g:String', 'g:URLSearchParams', 'g:structuredClone',
  'mod:querystring.stringify', 'mod:qs.stringify', 'mod:util.inspect', 'mod:util.format',
])
// A name bound more than once resolves to the binding the analyzer has something to say about.
const KNOWN = new Set([...CALL_CAP.keys(), ...SHELL_CALLS, ...READ_CONTENT, ...SEND_WITH_OPTIONS, 'g:require', 'g:process.env'])
const meaningful = (r: Ref | null): r is Ref => !!r && (r.name.startsWith('mod:') || KNOWN.has(r.name))

const UNWRAP = new Set(['ParenthesizedExpression', 'TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression', 'TSSatisfiesExpression', 'TypeCastExpression', 'AwaitExpression'])
const GLOBAL_ROOTS = new Set(['globalThis', 'global', 'window', 'self'])
const PATH_JOIN = new Set(['mod:path.join', 'mod:path.resolve', 'mod:path.normalize', 'mod:path.posix.join'])
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'extra', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'errors', 'tokens'])

const isNode = (v: unknown): v is N => !!v && typeof v === 'object' && typeof (v as N).type === 'string'
const isMember = (n: N) => n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression'
const kids = (n: N): N[] => Object.entries(n).flatMap(([k, v]) => SKIP_KEYS.has(k) ? [] : Array.isArray(v) ? v.filter(isNode) : isNode(v) ? [v] : [])
const flatten = (root: N): N[] => {
  const out: N[] = []
  const stack = [root]
  for (let n = stack.pop(); n; n = stack.pop()) {
    out.push(n)
    const children = kids(n)
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i])
  }
  return out
}

const normModule = (m: string): string => m.replace(/^node:/, '').replace(/^fs\/promises$/, 'fs.promises')
const moduleOf = (name: string): string | undefined =>
  name.startsWith('mod:') ? [...MODULE_CAP.keys()].find(m => name === `mod:${m}` || name.startsWith(`mod:${m}.`)) : undefined
const display = (name: string): string => moduleOf(name) ?? name.replace(/^(?:mod|g):/, '')
const pluginsFor = (file: string): ParserPlugin[] =>
  [...(/\.tsx$/.test(file) ? ['typescript', 'jsx'] : /\.[cm]?ts$/.test(file) ? ['typescript'] : ['jsx']), 'decorators-legacy', 'explicitResourceManagement'] as ParserPlugin[]

// Flow-insensitive alias table: identifier -> every expression it was bound to, in source order.
const collectAliases = (nodes: N[], onModule: (m: string) => void): Map<string, N[]> => {
  const alias = new Map<string, N[]>()
  const bind = (name: string, value: N) => {
    const bound = alias.get(name) ?? []
    alias.set(name, bound)
    bound[Math.min(bound.length, MAX_BINDINGS - 1)] = value
  }
  const member = (object: N, name: string): N => ({ type: 'MemberExpression', object, property: { type: 'Identifier', name }, computed: false })
  for (const n of nodes) {
    if (n.type === 'VariableDeclarator' && n.init) {
      if (n.id.type === 'Identifier') bind(n.id.name, n.init)
      if (n.id.type === 'ObjectPattern') {
        for (const p of n.id.properties) {
          const local = p.value?.type === 'AssignmentPattern' ? p.value.left : p.value
          const key = p.key?.name ?? p.key?.value
          if (p.type === 'ObjectProperty' && local?.type === 'Identifier' && key) bind(local.name, member(n.init, key))
        }
      }
    } else if (n.type === 'AssignmentExpression' && n.operator === '=' && n.left.type === 'Identifier') {
      bind(n.left.name, n.right)
    } else if (n.type === 'ImportDeclaration' && n.importKind !== 'type' && n.importKind !== 'typeof') {
      const mod = normModule(n.source.value)
      onModule(mod)
      const ref: N = { type: 'ModuleRef', name: `mod:${mod}` }
      for (const s of n.specifiers) {
        if (s.importKind === 'type') continue
        bind(s.local.name, s.type === 'ImportSpecifier' ? member(ref, s.imported.name ?? s.imported.value) : ref)
      }
    }
  }
  return alias
}

const createResolver = (alias: Map<string, N[]>, tick: () => void) => {
  const placeholder = (loose: boolean): Folded | null => (loose ? { value: '${}', literal: false } : null)
  const foldMemo = [new Map<N, Folded | null>(), new Map<N, Folded | null>()]
  const resolveMemo = new Map<N, Ref | null>()

  function fold(n: N | null | undefined, depth = 0, loose = false): Folded | null {
    if (!n) return placeholder(loose)
    const memo = foldMemo[Number(loose)]
    if (memo.has(n)) return memo.get(n) ?? null
    const f = foldNode(n, depth, loose)
    const result = f && f.value.length > MAX_FOLD_LENGTH ? placeholder(loose) : f
    memo.set(n, result)
    return result
  }

  function foldNode(n: N, depth: number, loose: boolean): Folded | null {
    tick()
    if (depth > MAX_DEPTH) return placeholder(loose)
    if (UNWRAP.has(n.type)) return fold(n.expression ?? n.argument, depth + 1, loose)
    switch (n.type) {
      case 'StringLiteral': return { value: n.value, literal: true }
      case 'TemplateLiteral': {
        const parts: string[] = []
        for (let i = 0; i < n.quasis.length; i++) {
          parts.push(n.quasis[i].value.cooked ?? '')
          if (n.expressions[i]) {
            const f = fold(n.expressions[i], depth + 1, loose)
            if (!f) return null
            parts.push(f.value)
          }
        }
        return { value: parts.join(''), literal: n.expressions.length === 0 }
      }
      case 'BinaryExpression': {
        if (n.operator !== '+') return placeholder(loose)
        const l = fold(n.left, depth + 1, loose)
        const r = fold(n.right, depth + 1, loose)
        return l && r ? { value: l.value + r.value, literal: false } : null
      }
      case 'Identifier': {
        const init = alias.get(n.name)?.at(-1)
        const f = init ? fold(init, depth + 1, loose) : n.name === '__dirname' || n.name === '__filename' ? { value: '.', literal: true } : null
        return f ? { value: f.value, literal: false } : placeholder(loose)
      }
      case 'MemberExpression': case 'OptionalMemberExpression':
        return /^g:process\.env\.(?:HOME|USERPROFILE)$/.test(resolve(n, depth + 1)?.name ?? '') ? { value: '~', literal: false } : placeholder(loose)
      case 'LogicalExpression': return fold(n.left, depth + 1) ?? fold(n.right, depth + 1, loose)
      case 'ConditionalExpression': return fold(n.consequent, depth + 1) ?? fold(n.alternate, depth + 1, loose)
      case 'CallExpression': case 'OptionalCallExpression': return foldCall(n, depth, loose) ?? placeholder(loose)
      default: return placeholder(loose)
    }
  }

  function foldCall(n: N, depth: number, loose: boolean): Folded | null {
    const callee: N = n.callee
    const args: N[] = n.arguments ?? []
    const name = resolve(callee, depth + 1)?.name ?? ''
    const prop = isMember(callee) && !callee.computed ? callee.property.name : undefined
    if (prop === 'join' && callee.object.type === 'ArrayExpression') {
      const parts = callee.object.elements.map((e: N) => fold(e, depth + 1, loose))
      const sep = args[0] ? fold(args[0], depth + 1, loose) : { value: ',', literal: true }
      return parts.every(Boolean) && sep ? { value: parts.map((p: Folded) => p.value).join(sep.value), literal: false } : null
    }
    if (name === 'g:String.fromCharCode' && args.every(a => a.type === 'NumericLiteral')) {
      return { value: String.fromCharCode(...args.map(a => a.value)), literal: false }
    }
    if (name === 'g:atob' && args[0]) {
      const inner = fold(args[0], depth + 1)
      return inner ? { value: Buffer.from(inner.value, 'base64').toString(), literal: false } : null
    }
    if (prop === 'toString' && callee.object.type === 'CallExpression' && resolve(callee.object.callee, depth + 1)?.name === 'g:Buffer.from') {
      const [data, enc] = callee.object.arguments
      const inner = fold(data, depth + 1)
      return inner && fold(enc, depth + 1)?.value === 'base64' ? { value: Buffer.from(inner.value, 'base64').toString(), literal: false } : null
    }
    if (PATH_JOIN.has(name)) {
      const parts = args.map(a => fold(a, depth + 1, loose))
      return parts.every(Boolean) ? { value: parts.map(p => p!.value).join('/').replace(/\/{2,}/g, '/'), literal: false } : null
    }
    return name === 'mod:os.homedir' ? { value: '~', literal: false } : null
  }

  function moduleRef(arg: N | undefined, depth: number): Ref | null {
    const f = fold(arg, depth + 1)
    return f ? { name: `mod:${normModule(f.value)}`, folded: !f.literal } : null
  }

  function resolveCall(n: N, depth: number): Ref | null {
    if (n.type === 'ImportExpression' || n.callee?.type === 'Import') return moduleRef(n.source ?? n.arguments?.[0], depth)
    const fn = resolve(n.callee, depth + 1)
    switch (fn?.name) {
      case 'g:require': return moduleRef(n.arguments?.[0], depth)
      case 'mod:module.createRequire': return { name: 'g:require', folded: false }
      case 'mod:util.promisify': return resolve(n.arguments?.[0], depth + 1)
      default: return null
    }
  }

  function resolve(n: N | null | undefined, depth = 0): Ref | null {
    if (!n) return null
    if (resolveMemo.has(n)) return resolveMemo.get(n) ?? null
    const r = resolveNode(n, depth)
    resolveMemo.set(n, r)
    return r
  }

  function resolveNode(n: N, depth: number): Ref | null {
    tick()
    if (depth > MAX_DEPTH) return null
    if (UNWRAP.has(n.type)) return resolve(n.expression ?? n.argument, depth + 1)
    switch (n.type) {
      case 'ModuleRef': return { name: n.name, folded: false }
      case 'Identifier': {
        const bound = alias.get(n.name)
        if (!bound) return { name: GLOBAL_ROOTS.has(n.name) ? 'g:' : `g:${n.name}`, folded: false }
        let fallback: Ref | null = null
        for (const b of bound) {
          const r = resolve(b, depth + 1)
          if (meaningful(r)) return r
          fallback ??= r
        }
        return fallback
      }
      case 'MemberExpression': case 'OptionalMemberExpression': {
        const base = resolve(n.object, depth + 1)
        const prop = n.computed ? fold(n.property, depth + 1) : n.property.type === 'Identifier' ? { value: n.property.name, literal: true } : null
        return base && prop ? { name: base.name === 'g:' ? `g:${prop.value}` : `${base.name}.${prop.value}`, folded: base.folded || !prop.literal } : null
      }
      case 'CallExpression': case 'OptionalCallExpression': case 'ImportExpression': return resolveCall(n, depth)
      default: return null
    }
  }

  return { fold, resolve }
}

const keyOf = (p: N): string | undefined => p.key?.name ?? p.key?.value

const parseSource = (source: string, file: string, plugins: ParserPlugin[]) =>
  parse(source, { sourceType: 'unambiguous', errorRecovery: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true, plugins })

// Plain JS may carry Flow annotations, which the default plugins reject; retry once with Flow.
const parseWithFallback = (source: string, file: string) => {
  const plugins = pluginsFor(file)
  try {
    return parseSource(source, file, plugins)
  } catch (error) {
    if (!plugins.includes('typescript') && !plugins.includes('flow')) return parseSource(source, file, [...plugins, 'flow'])
    throw error
  }
}

const analyze = (source: string, file: string, map: SensitivityMap): JsEvidence => {
  const ast = parseWithFallback(source, file)
  const nodes = flatten(ast.program as N)
  const lines = source.split('\n')
  const pathMap = withoutProcessEnv(map)
  const capabilities = new Set<Capability>()
  const sources: Source[] = []
  const sinks: Sink[] = []
  const obfuscated = new Map<string, Obfuscation>()
  const addModule = (m: string) => { const cap = MODULE_CAP.get(moduleOf(`mod:${m}`) ?? ''); if (cap) capabilities.add(cap) }
  const alias = collectAliases(nodes, addModule)
  let steps = 0
  const tick = () => { if (++steps > MAX_STEPS) throw new Error('analysis budget exceeded') }
  const { fold, resolve } = createResolver(alias, tick)
  const snippetAt = (line: number) => redactSecrets((lines[line - 1] ?? '').trim()).slice(0, 200)
  const lineOf = (n: N) => n.loc?.start.line ?? 1

  // The whole environment counts only when it is serialised into the arguments of a send, directly or
  // through an alias. Handing it to a config loader (cleanEnv(process.env)) is routine and does not count.
  const wholeEnv = (n: N | null | undefined, hops = 0, seen = new Set<N>()): N | null => {
    if (!n || hops > MAX_ALIAS_HOPS || seen.has(n)) return null
    tick()
    seen.add(n)
    if (isMember(n)) {
      if (resolve(n)?.name === 'g:process.env') return n
      if (resolve(n.object)?.name === 'g:process.env') return null
    }
    const look = (nodes: ReadonlyArray<N | null | undefined>, h = hops): N | null => {
      for (const c of nodes) { const hit = wholeEnv(c, h, seen); if (hit) return hit }
      return null
    }
    if (n.type === 'Identifier') return look(alias.get(n.name) ?? [], hops + 1)
    if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression' || n.type === 'NewExpression') {
      const serialises = SERIALIZERS.has(resolve(n.callee)?.name ?? '')
      return look([...(serialises ? n.arguments : []), isMember(n.callee) ? n.callee.object : null])
    }
    return look(kids(n))
  }

  const objectArg = (a: N | undefined): N | undefined => a?.type === 'Identifier' ? alias.get(a.name)?.find(b => b.type === 'ObjectExpression') : a
  const sends = (args: N[]): boolean => args.map(objectArg).some(o => o?.type === 'ObjectExpression' && o.properties.some((p: N) =>
    p.type === 'ObjectProperty' && (BODY_KEYS.has(keyOf(p) ?? '') || (keyOf(p) === 'method' && /^(?:post|put|patch)$/i.test(fold(p.value)?.value ?? '')))))
  const optionHost = (args: N[]): string | undefined => {
    const o = args.map(objectArg).find(a => a?.type === 'ObjectExpression')
    const p = o?.properties.find((x: N) => x.type === 'ObjectProperty' && ['host', 'hostname'].includes(keyOf(x) ?? ''))
    return p ? fold(p.value)?.value : undefined
  }
  const shellCommand = (n: N): string | undefined => {
    if (n.type === 'TaggedTemplateExpression') return fold(n.quasi, 0, true)?.value
    const [cmd, argv] = n.arguments as N[]
    const rest = argv?.type === 'ArrayExpression' ? argv.elements.map((e: N) => fold(e, 0, true)?.value ?? '${}').join(' ') : ''
    const head = fold(cmd, 0, true)?.value
    return head === undefined ? undefined : `${head} ${rest}`.trim()
  }

  for (const n of nodes) {
    if (isMember(n) && /^g:(?:process|Bun)\.env(?:\.|$)|^g:Deno\.env(?:\.|$)/.test(resolve(n)?.name ?? '')) capabilities.add('credentials')
    const callee = n.type === 'TaggedTemplateExpression' ? n.tag : n.callee
    if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      const mod = resolve(n)
      if (mod?.name.startsWith('mod:')) {
        addModule(mod.name.slice(4))
        if (mod.folded && moduleOf(mod.name)) obfuscated.set(`${lineOf(n)}:${display(mod.name)}`, { line: lineOf(n), name: display(mod.name) })
      }
    }
    if (!['CallExpression', 'OptionalCallExpression', 'NewExpression', 'TaggedTemplateExpression'].includes(n.type)) continue
    const ref = resolve(callee)
    if (!ref) continue
    const line = lineOf(n)
    const args: N[] = n.arguments ?? []
    const shell = SHELL_CALLS.has(ref.name)
    const sender = SEND_ALWAYS.test(ref.name) || SEND_WITH_OPTIONS.has(ref.name)
    const cap = CALL_CAP.get(ref.name) ?? (shell ? 'shell' : undefined)
    const modCap = MODULE_CAP.get(moduleOf(ref.name) ?? '')
    if (cap) capabilities.add(cap)
    if (modCap) capabilities.add(modCap)
    if (ref.folded && (cap || modCap || sender)) obfuscated.set(`${line}:${display(ref.name)}`, { line, name: display(ref.name) })

    if (READ_CONTENT.has(ref.name)) {
      const path = fold(args[0])
      const level = path ? classifyPath(path.value, pathMap).level : 'low'
      if (level === 'critical' || level === 'high') {
        capabilities.add('credentials')
        sources.push({ line, strong: level === 'critical', snippet: snippetAt(line) })
      }
    }
    if (shell) {
      const cmd = shellCommand(n)
      const found = cmd ? scanLines(cmd.split('\n'), map) : { sources: [], sinks: [] }
      sources.push(...found.sources.map(s => ({ ...s, line, snippet: snippetAt(line) })))
      sinks.push(...found.sinks.map(s => ({ ...s, line, snippet: snippetAt(line) })))
    }
    if (sender && (SEND_ALWAYS.test(ref.name) || sends(args))) {
      const host = hostOf(fold(args[0], 0, true)?.value ?? '') ?? optionHost(args)
      if (!isLocalHost(host)) {
        sinks.push({ line, snippet: snippetAt(line), host })
        const env = args.map(a => wholeEnv(a)).find(Boolean)
        if (env) sources.push({ line: lineOf(env), strong: true, snippet: snippetAt(lineOf(env)) })
      }
    }
  }
  return { parsed: true, capabilities, sources, sinks, obfuscated: [...obfuscated.values()] }
}

const cache = new WeakMap<SensitivityMap, Map<string, JsEvidence>>()

export const analyzeJsFile = (source: string, file: string, map: SensitivityMap): JsEvidence => {
  if (source.length > MAX_BYTES) return UNPARSED
  const perMap = cache.get(map) ?? new Map<string, JsEvidence>()
  cache.set(map, perMap)
  const key = `${file}\0${source}`
  const hit = perMap.get(key)
  if (hit) return hit
  let evidence: JsEvidence
  try {
    evidence = analyze(source, file, map)
  } catch {
    evidence = UNPARSED
  }
  perMap.set(key, evidence)
  return evidence
}
