#!/usr/bin/env node
// Prints the coverage numbers shown in the README's "Hardened release by
// release" callout, so the figures can be kept honest on every release:
//   - reproduced attack techniques  = one bullet per `### Security` CHANGELOG entry
//   - interceptors                  = *.interceptor.ts files
//   - capability classes            = entries in the CAPABILITIES tuple
//
// Usage: npm run coverage:count   (then update the README number if it changed)
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function securityBullets() {
  const lines = readFileSync(join(root, 'CHANGELOG.md'), 'utf8').split('\n');
  let inSecurity = false;
  let count = 0;
  for (const line of lines) {
    if (line.startsWith('## ['))
      inSecurity = false; // new version resets
    else if (line.startsWith('### Security')) inSecurity = true;
    else if (line.startsWith('### '))
      inSecurity = false; // a different subsection
    else if (inSecurity && line.startsWith('- **')) count++;
  }
  return count;
}

function interceptors() {
  return readdirSync(join(root, 'src/adapters/interceptors')).filter((f) =>
    f.endsWith('.interceptor.ts'),
  ).length;
}

function capabilities() {
  const src = readFileSync(join(root, 'src/domain/capability.ts'), 'utf8');
  const match = src.match(/CAPABILITIES\s*=\s*\[([\s\S]*?)\]/);
  if (!match) return 0;
  return (match[1].match(/'[^']+'/g) ?? []).length;
}

const techniques = securityBullets();
const ints = interceptors();
const caps = capabilities();

console.log(
  `reproduced attack techniques (CHANGELOG ### Security bullets): ${techniques}`,
);
console.log(`interceptors: ${ints}`);
console.log(`capability classes: ${caps}`);
console.log(
  `\nREADME line should read: "${caps} capability classes across ${ints} interceptors … ${techniques} reproduced attack techniques blocked"`,
);
