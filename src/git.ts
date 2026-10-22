import { spawnSync } from 'node:child_process'

export type GitWorktreeState = {
  /** `true` only when `git rev-parse --is-inside-work-tree` answered `true` for the target. */
  insideWorktree: boolean
  /** Porcelain status entries limited to the target directory; `null` when git could not answer. */
  pending: string[] | null
}

function git(root: string, args: string[]): { status: number, stdout: string } | null {
  const result = spawnSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', ...args], {
    cwd: root,
    env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_CONFIG_NOSYSTEM: '1' },
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 4 * 1_048_576,
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  if (result.error || result.status === null) return null
  return { status: result.status, stdout: result.stdout }
}

/**
 * Inspects the target as a git working tree. The apply mode requires one because `git` is the
 * only undo available for the files it writes.
 */
export function gitWorktreeState(root: string): GitWorktreeState {
  const inside = git(root, ['rev-parse', '--is-inside-work-tree'])
  if (!inside || inside.status !== 0 || inside.stdout.trim() !== 'true') return { insideWorktree: false, pending: null }
  const status = git(root, ['status', '--porcelain', '--', '.'])
  if (!status || status.status !== 0) return { insideWorktree: true, pending: null }
  return { insideWorktree: true, pending: status.stdout.split(/\r?\n/).map((line) => line.trimEnd()).filter(Boolean) }
}
