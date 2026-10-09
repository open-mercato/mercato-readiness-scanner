import fs from 'node:fs'

fs.chmodSync(new URL('../dist/cli.js', import.meta.url), 0o755)
