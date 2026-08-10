import type { PackagePolicy } from '../../domain/policy.js';
import type { PolicyDraft } from '../../domain/policy-draft.js';

/**
 * Render a {@link PolicyDraft} as the source of a `dephawk.config.js`.
 *
 * Written by hand rather than `JSON.stringify`, because the comments are the
 * point. A generated allowlist is only safe if someone reads it, and nobody
 * reads a wall of anonymous hostnames — so every package carries the
 * observations that produced its rules, and anything granting open-ended power
 * is called out where the reviewer will see it.
 */
export function renderConfig(draft: PolicyDraft): string {
  const lines: string[] = [];

  lines.push('// dephawk policy, drafted from an observed run.');
  lines.push('//');
  lines.push('// Everything below was granted because it HAPPENED, not because');
  lines.push('// it is safe. dephawk cannot tell a legitimate API call from');
  lines.push('// exfiltration — if something malicious was already installed, its');
  lines.push('// behaviour is in here too. Read it before you trust it, and delete');
  lines.push('// anything you cannot explain.');
  lines.push('//');
  lines.push('// Re-draft at any time:  dephawk init <command>');
  lines.push('');

  const review = draft.notes.filter((note) => note.needsReview.length > 0);
  if (review.length > 0) {
    lines.push('// Look at these first — they grant open-ended power, not access to');
    lines.push('// one named thing:');
    for (const note of review) {
      lines.push(`//   ${note.package}: ${note.needsReview.join(', ')}`);
    }
    lines.push('');
  }

  if (draft.unattributed.length > 0) {
    lines.push('// dephawk could not attribute these to any package, so they are NOT');
    lines.push('// granted below — the only place to put them is the default bucket,');
    lines.push('// which would weaken it for everything at once. Work out who is');
    lines.push('// responsible before allowing them:');
    for (const finding of draft.unattributed) {
      lines.push(`//   ${finding}`);
    }
    lines.push('');
  }

  lines.push('export default {');
  lines.push(`  mode: ${quote(draft.policy.mode)},`);
  lines.push('');
  lines.push('  // Applied to any package not listed below. Deny by default is what');
  lines.push('  // makes the list above mean anything.');
  lines.push(`  default: ${renderInline(draft.policy.default)},`);
  lines.push('');

  const names = Object.keys(draft.policy.packages);
  if (names.length === 0) {
    lines.push('  // Nothing needed a rule: the run touched nothing sensitive.');
    lines.push('  packages: {},');
  } else {
    lines.push('  packages: {');
    names.forEach((name, index) => {
      const note = draft.notes.find((candidate) => candidate.package === name);
      for (const observation of note?.observations ?? []) {
        lines.push(`    // ${observation}`);
      }
      lines.push(`    ${key(name)}: ${renderInline(draft.policy.packages[name]!)},`);
      if (index < names.length - 1) {
        lines.push('');
      }
    });
    lines.push('  },');
  }

  lines.push('};');
  return `${lines.join('\n')}\n`;
}

/** A package policy on one line, or spread when it would be unreadable. */
function renderInline(policy: PackagePolicy): string {
  const parts: string[] = [];

  if (policy.net !== undefined) {
    const net: string[] = [`connect: ${renderArray(policy.net.connect ?? [])}`];
    if (policy.net.listen !== undefined) {
      net.push(`listen: ${String(policy.net.listen)}`);
    }
    parts.push(`net: { ${net.join(', ')} }`);
  }
  if (policy.fs !== undefined) {
    const fs: string[] = [];
    if (policy.fs.read !== undefined) {
      fs.push(`read: ${renderArray(policy.fs.read)}`);
    }
    if (policy.fs.write !== undefined) {
      fs.push(`write: ${renderArray(policy.fs.write)}`);
    }
    parts.push(`fs: { ${fs.join(', ')} }`);
  }
  if (policy.spawn !== undefined) {
    parts.push(`spawn: ${String(policy.spawn)}`);
  }
  if (policy.native !== undefined) {
    parts.push(`native: ${String(policy.native)}`);
  }
  if (policy.eval !== undefined) {
    parts.push(`eval: ${String(policy.eval)}`);
  }
  if (policy.env !== undefined) {
    parts.push(
      `env: ${typeof policy.env === 'boolean' ? String(policy.env) : renderArray(policy.env)}`,
    );
  }

  return parts.length === 0 ? '{}' : `{ ${parts.join(', ')} }`;
}

function renderArray(values: readonly string[]): string {
  return values.length === 0 ? '[]' : `[${values.map(quote).join(', ')}]`;
}

/** A valid identifier stays bare; anything else (scoped names) is quoted. */
function key(name: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(name) ? name : quote(name);
}

function quote(value: string): string {
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}
