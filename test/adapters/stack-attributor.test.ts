import { describe, it, expect } from 'vitest';
import { StackAttributor } from '../../src/adapters/attribution/stack-attributor.js';

const attributor = new StackAttributor();

describe('StackAttributor', () => {
  it('attributes to the first node_modules package, skipping dephawk', () => {
    const stack = [
      'Error',
      '    at readFileSync (node:fs:100:5)',
      '    at Object.<anonymous> (/proj/node_modules/dephawk/dist/register.js:1:1)',
      '    at steal (/proj/node_modules/evil-pkg/index.js:10:3)',
      '    at main (/proj/app.js:5:1)',
    ].join('\n');

    const result = attributor.attribute(stack);
    expect(result.package).toBe('evil-pkg');
    // dephawk frame is stripped from the display frames
    expect(result.frames.some((f) => f.includes('dephawk'))).toBe(false);
    expect(result.frames.some((f) => f.includes('evil-pkg'))).toBe(true);
  });

  it('handles scoped packages', () => {
    const stack = '    at x (/p/node_modules/@acme/tool/lib.js:2:2)';
    expect(attributor.attribute(stack).package).toBe('@acme/tool');
  });

  it('returns the deepest package for nested node_modules', () => {
    const stack = '    at y (/p/node_modules/a/node_modules/b/index.js:1:1)';
    expect(attributor.attribute(stack).package).toBe('b');
  });

  it('returns null for app code with no node_modules frame', () => {
    const stack = ['Error', '    at main (/proj/app.js:1:1)'].join('\n');
    const result = attributor.attribute(stack);
    expect(result.package).toBeNull();
    expect(result.frames).toEqual(['at main (/proj/app.js:1:1)']);
  });

  it('normalises Windows backslash paths', () => {
    const stack = '    at z (C:\\proj\\node_modules\\win-pkg\\index.js:1:1)';
    expect(attributor.attribute(stack).package).toBe('win-pkg');
  });

  it('ignores malformed scoped paths', () => {
    const stack = '    at q (/p/node_modules/@scope)';
    expect(attributor.attribute(stack).package).toBeNull();
  });

  it('respects maxFrames', () => {
    const limited = new StackAttributor({ maxFrames: 2 });
    const stack = [
      '    at a (/p/node_modules/x/i.js:1:1)',
      '    at b (/p/app1.js:1:1)',
      '    at c (/p/app2.js:1:1)',
      '    at d (/p/app3.js:1:1)',
    ].join('\n');
    expect(limited.attribute(stack).frames).toHaveLength(2);
  });

  it('honours a custom self package name', () => {
    const custom = new StackAttributor({ selfPackage: 'my-guard' });
    const stack = [
      '    at g (/p/node_modules/my-guard/index.js:1:1)',
      '    at h (/p/node_modules/real-pkg/index.js:1:1)',
    ].join('\n');
    expect(custom.attribute(stack).package).toBe('real-pkg');
  });
});
