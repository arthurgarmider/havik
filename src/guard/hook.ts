import { hookMain } from './hook-main'

// The hook an agent runs on every event: `node guard.mjs [--agent <id>]`. The standalone program runs the same as `havik hook`.
const flag = process.argv.indexOf('--agent')
void hookMain(flag > 0 ? process.argv[flag + 1] : undefined)
