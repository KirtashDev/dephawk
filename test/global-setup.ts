import { execSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Rebuild `dist/` before the suite when it is older than the sources.
 *
 * The e2e tests run the *built* CLI, and each of them only rebuilt when `dist`
 * was **missing**. That is the wrong question: after any source change `dist`
 * still exists, so a full green e2e run could be testing the previous build
 * entirely. Twice now a real regression was only caught because the build
 * happened to be refreshed by hand first — a coin flip, not a test.
 *
 * Comparing mtimes rather than always building keeps the common case (nothing
 * changed) free.
 */
const root = resolve(import.meta.dirname, '..');
const BUILD_OUTPUTS = ['dist/cli.js', 'dist/register.js', 'dist/index.js'];
const BUILD_INPUTS = ['src', 'tsup.config.ts', 'package.json'];

function newestMtime(path: string): number {
  const stats = statSync(path);
  if (!stats.isDirectory()) {
    return stats.mtimeMs;
  }
  let newest = stats.mtimeMs;
  for (const entry of readdirSync(path)) {
    newest = Math.max(newest, newestMtime(join(path, entry)));
  }
  return newest;
}

export function setup(): void {
  const outputs = BUILD_OUTPUTS.map((file) => join(root, file));
  if (!outputs.every((file) => existsSync(file))) {
    execSync('npm run build', { cwd: root, stdio: 'ignore' });
    return;
  }
  const built = Math.min(...outputs.map((file) => statSync(file).mtimeMs));
  const sources = Math.max(
    ...BUILD_INPUTS.map((entry) => newestMtime(join(root, entry))),
  );
  if (sources > built) {
    execSync('npm run build', { cwd: root, stdio: 'ignore' });
  }
}
