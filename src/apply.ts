import fs from 'node:fs'
import path from 'node:path'
import { isCredentialPath, isLiveEnvPath } from './files.js'
import { RULES } from './rules.js'
import type { ResolvedTarget } from './scan.js'
import type { AppliedChange, ApplyOutcome, ApplyPlan, AutofixAction, ScanReport } from './types.js'

/**
 * Raised when a write would leave the purely additive contract — an existing path, a symlink,
 * a path outside the application root, a secret-bearing path, or unparsable JSON.
 */
export class ApplyRefusedError extends Error {
  override name = 'ApplyRefusedError'
}

/**
 * Plans the safe, purely additive work for a scanned application.
 *
 * Only rules that failed are considered. A failing rule is planned when its autofix descriptor
 * is `safe-additive` and still has something to add; everything else lands in `skipped` with the
 * reason and its documentation URL.
 */
export function planApply(target: ResolvedTarget, report: ScanReport): ApplyPlan {
  const plan: ApplyPlan = { root: target.root, planned: [], skipped: [] }
  const byId = new Map(RULES.map((rule) => [rule.id, rule]))
  for (const result of report.results) {
    if (result.status !== 'fail') continue
    const rule = byId.get(result.id)
    if (!rule) continue
    const { id, title, severity, docsUrl } = result
    if (rule.autofix.safety === 'manual-only') {
      plan.skipped.push({ id, title, severity, status: result.status, reason: rule.autofix.reason, docsUrl })
      continue
    }
    const actions = rule.autofix.plan(target.context)
    if (!actions.length) {
      plan.skipped.push({ id, title, severity, status: result.status, reason: 'No purely additive action remains; the rest of this rule needs a manual edit.', docsUrl })
      continue
    }
    plan.planned.push({ id, title, severity, actions })
  }
  return plan
}

export function applyPlan(plan: ApplyPlan, dryRun: boolean): ApplyOutcome {
  const changes: AppliedChange[] = []
  for (const fix of plan.planned) {
    for (const action of fix.actions) {
      changes.push(dryRun ? previewAction(fix.id, action) : performAction(plan.root, fix.id, action))
    }
  }
  return { plan, changes, dryRun }
}

export function actionPath(action: AutofixAction): string {
  return action.kind === 'add-npm-script' ? 'package.json' : action.path
}

function previewAction(id: string, action: AutofixAction): AppliedChange {
  return { id, description: action.description, path: actionPath(action), changed: false, note: 'planned only (dry run)' }
}

function performAction(root: string, id: string, action: AutofixAction): AppliedChange {
  const base = { id, description: action.description, path: actionPath(action) }
  if (action.kind === 'create-file') return { ...base, ...createFile(root, action.path, action.contents) }
  if (action.kind === 'append-lines') return { ...base, ...appendLines(root, action.path, action.lines, action.force ?? false) }
  return { ...base, ...addNpmScript(root, action.name, action.value) }
}

type WriteResult = { changed: boolean, note: string | null }

/**
 * Resolves a write target inside the application root. Refuses absolute paths, traversal,
 * secret-bearing paths, and any path whose existing ancestors include a symlink, so a write can
 * never escape the scanned application.
 */
function resolveWritable(root: string, relativePath: string): string {
  if (path.isAbsolute(relativePath)) throw new ApplyRefusedError(`Refusing to write an absolute path: ${relativePath}`)
  if (isLiveEnvPath(relativePath) || isCredentialPath(relativePath)) throw new ApplyRefusedError(`Refusing to write the secret-bearing path ${relativePath}.`)
  const absolute = path.resolve(root, relativePath)
  const relation = path.relative(root, absolute)
  if (!relation || relation === '..' || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) {
    throw new ApplyRefusedError(`Refusing to write outside the application root: ${relativePath}`)
  }
  let current = root
  for (const segment of relation.split(path.sep)) {
    current = path.join(current, segment)
    let stat: fs.Stats
    try {
      stat = fs.lstatSync(current)
    } catch {
      continue
    }
    if (stat.isSymbolicLink()) throw new ApplyRefusedError(`Refusing to write through the symlink ${path.relative(root, current)}.`)
  }
  return absolute
}

function createFile(root: string, relativePath: string, contents: string): WriteResult {
  const absolute = resolveWritable(root, relativePath)
  if (fs.existsSync(absolute)) return { changed: false, note: 'already present; left untouched' }
  fs.mkdirSync(path.dirname(absolute), { recursive: true })
  try {
    // 'wx' fails instead of truncating if anything appeared at the path in the meantime.
    fs.writeFileSync(absolute, contents, { encoding: 'utf8', flag: 'wx' })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return { changed: false, note: 'already present; left untouched' }
    throw error
  }
  return { changed: true, note: null }
}

function appendLines(root: string, relativePath: string, lines: string[], force = false): WriteResult {
  const absolute = resolveWritable(root, relativePath)
  let stat: fs.Stats
  try {
    stat = fs.lstatSync(absolute)
  } catch {
    return createFile(root, relativePath, `${lines.join('\n')}\n`)
  }
  if (!stat.isFile()) throw new ApplyRefusedError(`Refusing to append to ${relativePath}: it is not a regular file.`)
  const existing = fs.readFileSync(absolute, 'utf8')
  const present = new Set(existing.split(/\r?\n/).map((line) => line.trim()))
  // A forced append trusts the planner: it already decided from the file's *effective* state that
  // the line is needed, which a verbatim-presence check cannot see.
  const absent = force ? lines : lines.filter((line) => !present.has(line.trim()))
  if (!absent.length) return { changed: false, note: 'every line already present; left untouched' }
  const separator = existing.length === 0 || existing.endsWith('\n') ? '' : '\n'
  // 'a' only ever adds bytes at the end of the file; existing content is never rewritten.
  fs.appendFileSync(absolute, `${separator}# Added by mercato-readiness apply\n${absent.join('\n')}\n`, { encoding: 'utf8', flag: 'a' })
  return { changed: true, note: null }
}

function detectIndent(source: string): string | number {
  return source.match(/\n([ \t]+)"/)?.[1] ?? 0
}

/**
 * Inserts one missing `scripts` key into package.json.
 *
 * The edit is performed only when the file round-trips byte-for-byte through
 * `JSON.parse`/`JSON.stringify`, which proves the inserted key is the only resulting difference.
 * Any existing value is left alone.
 */
function addNpmScript(root: string, name: string, value: string): WriteResult {
  const absolute = resolveWritable(root, 'package.json')
  const original = fs.readFileSync(absolute, 'utf8')
  let parsed: unknown
  try {
    parsed = JSON.parse(original)
  } catch {
    throw new ApplyRefusedError('Refusing to edit package.json: it is not valid JSON.')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new ApplyRefusedError('Refusing to edit package.json: it is not a JSON object.')
  const manifest = parsed as Record<string, unknown>
  const indent = detectIndent(original)
  const trailing = original.endsWith('\n') ? '\n' : ''
  if (`${JSON.stringify(manifest, null, indent)}${trailing}` !== original) {
    return { changed: false, note: 'package.json formatting is not reproducible, so no key was inserted; add the script by hand' }
  }
  const scripts = manifest.scripts
  if (scripts !== undefined && (scripts === null || typeof scripts !== 'object' || Array.isArray(scripts))) {
    throw new ApplyRefusedError('Refusing to edit package.json: "scripts" is not an object.')
  }
  const existing = (scripts ?? {}) as Record<string, unknown>
  if (existing[name] !== undefined) return { changed: false, note: 'script already defined; left untouched' }
  manifest.scripts = { ...existing, [name]: value }
  const updated = `${JSON.stringify(manifest, null, indent)}${trailing}`
  const temporary = `${absolute}.tmp-${process.pid}`
  fs.writeFileSync(temporary, updated, { encoding: 'utf8', mode: fs.statSync(absolute).mode & 0o777 })
  fs.renameSync(temporary, absolute)
  return { changed: true, note: null }
}
