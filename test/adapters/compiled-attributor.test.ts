import { describe, it, expect, afterEach } from 'vitest';
import { CompiledAttributor } from '../../src/adapters/attribution/compiled-attributor.js';
import { StackAttributor } from '../../src/adapters/attribution/stack-attributor.js';
import {
  noteCompiledFilename,
  resetCompiledFilenames,
} from '../../src/adapters/attribution/compiled-context.js';

const attributor = new CompiledAttributor(new StackAttributor({ selfRoot: null }));

afterEach(() => {
  resetCompiledFilenames();
});

describe('CompiledAttributor', () => {
  it('leaves ordinary stacks alone when vm has never been used', () => {
    const stack = ['Error', '    at steal (/proj/node_modules/evil/index.js:1:1)'].join(
      '\n',
    );
    expect(attributor.attribute(stack).package).toBe('evil');
  });

  it('refuses to credit a frame at a filename vm was handed', () => {
    // `runInThisContext(code, { filename: '…/innocent/index.js' })` makes the
    // compiled code report frames at a path its caller chose. Believing them
    // hands the call to `innocent`, along with innocent's allowlist.
    noteCompiledFilename('/proj/node_modules/innocent/index.js');

    const stack = [
      'Error',
      '    at readFileSync (node:fs:100:5)',
      '    at /proj/node_modules/innocent/index.js:1:26',
      '    at run (/proj/node_modules/evil/index.js:10:3)',
    ].join('\n');

    const result = attributor.attribute(stack);
    expect(result.package).toBe('evil');
    expect(result.origin).toBe('dependency');
    // The disguised frame describes a file that never ran anything, so it is
    // not shown either.
    expect(result.frames.some((f) => f.includes('innocent'))).toBe(false);
  });

  it('still trusts that package’s genuinely different files', () => {
    // Only the exact name handed to vm is distrusted, not the whole package.
    noteCompiledFilename('/proj/node_modules/innocent/index.js');

    const stack = [
      'Error',
      '    at helper (/proj/node_modules/innocent/lib/real.js:4:2)',
    ].join('\n');
    expect(attributor.attribute(stack).package).toBe('innocent');
  });

  it('falls back to unknown when the disguise is all there was', () => {
    // Nothing real underneath: held to the default policy bucket rather than
    // credited to the package whose name was borrowed.
    noteCompiledFilename('/proj/node_modules/innocent/index.js');

    const stack = ['Error', '    at /proj/node_modules/innocent/index.js:1:1'].join('\n');
    const result = attributor.attribute(stack);
    expect(result.package).toBeNull();
    expect(result.origin).toBe('unknown');
  });
});
