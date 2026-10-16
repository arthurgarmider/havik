# havik conventions

Bun for development and tests; the published package is a Node 20+ bundle (`bun run build` makes `dist/havik.js`).

- No `Bun.*` in `src/`. File access goes through `core/fs.ts` (`readText`, `readTextOrNull`, `fileExists`, `findFiles`).
- Adapter and analyzer entry points return `Result<T>` instead of throwing and are wrapped in `trace('name', fn)`, which logs only under `HAVIK_DEBUG=1`, with secrets redacted. Small pure helpers are plain functions.
- A layer that fails or a file that cannot be read becomes a `warnings` entry (scan exit code 3). Never return an empty result that reads as "nothing found".
- No semicolons, single quotes, two-space indent, no inline logging.
- A detection change starts with a fixture in `tests/fixtures/attacks` or `benign` and a failing test. The fixtures are the spec; anything they do not exercise is a known gap in the README.
- A scanned tree is untrusted input: read its JSON and YAML through `core/json.ts`, and keep any path it names inside the scan root with `isInside` from `core/paths.ts`.
- AI checks (`src/ai`) are opt-in and only add findings. The TypeSafe client is injected (`Judge`), so tests use a stub or `tests/helpers/fake-jev.ts`; redact first, then shorten, and send no source files, `.env` or MCP values.
- The guard (`src/guard`) is detect-only: `hook.ts` always exits 0 and prints nothing or one `{"systemMessage"}` object, never a permission decision or changed input/output. Tests run it in a child process with `HOME`, `HAVIK_HOME` and `TMPDIR` in a temp dir (`tests/helpers/guard-cli.ts`); CI also runs them against `node dist/guard.js` (`HAVIK_GUARD`).
- Never print or store a secret value. Use `core/redact.ts` (`redactSecrets`, `containsSecret`); MCP env and header values are reduced to key names at parse time.
- Every rule id that code can emit must appear in the README (`tests/unit/readme.test.ts` enforces it).
- `bun test` and `bun run typecheck` must both pass. CLI tests honour `HAVIK_CLI="node dist/havik.js"`.
- Measure a change against real skills before shipping it: `havik scan ~/.claude` and count findings by rule.
