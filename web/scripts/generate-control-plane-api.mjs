import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
const webRoot = path.resolve(scriptDirectory, '..')
const repoRoot = path.resolve(webRoot, '..')
const specPath = path.join(webRoot, 'openapi', 'control-plane.json')
const outputPath = path.join(webRoot, 'src', 'lib', 'api', 'generated', 'openapi.ts')

mkdirSync(path.dirname(specPath), { recursive: true })
mkdirSync(path.dirname(outputPath), { recursive: true })

const rawSpec = execFileSync('go', ['run', './cmd/openapi-export'], {
  cwd: repoRoot,
  encoding: 'utf8',
})
const formattedSpec = `${JSON.stringify(JSON.parse(rawSpec), null, 2)}\n`
writeFileSync(specPath, formattedSpec)

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm'
execFileSync(
  npmCommand,
  ['exec', 'openapi-typescript', '--', path.relative(webRoot, specPath), '-o', path.relative(webRoot, outputPath)],
  {
    cwd: webRoot,
    stdio: 'inherit',
  },
)
