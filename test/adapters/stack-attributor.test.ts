import { describe, it, expect } from 'vitest';
import { StackAttributor } from '../../src/adapters/attribution/stack-attributor.js';
import { EVAL_FRAME } from '../../src/adapters/interceptors/support.js';

// selfRoot is pinned to null so these fixtures are judged only on their own
// content — the default (this module's directory) is irrelevant to /proj paths.
const attributor = new StackAttributor({ selfRoot: null });

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
    expect(result.origin).toBe('dependency');
    // dephawk frame is stripped from the display frames
    expect(result.frames.some((f) => f.includes('dephawk'))).toBe(false);
    expect(result.frames.some((f) => f.includes('evil-pkg'))).toBe(true);
  });

  it('does not let an eval frame pin the call on another package', () => {
    // `eval("//# sourceURL=…/innocent/index.js\n …")` makes V8 report the
    // evaluated code at a location the attacker chose. Without this, the read
    // was attributed to `innocent` — and borrowed its allowlist.
    const stack = [
      'Error',
      '    at readFileSync (node:fs:100:5)',
      '    at eval (/proj/node_modules/innocent/index.js:2:26)',
      '    at steal (/proj/node_modules/evil-pkg/index.js:10:3)',
      '    at main (/proj/app.js:5:1)',
    ].join('\n');

    const result = attributor.attribute(stack);
    // The package that ran the eval is the culprit, not the one it named.
    expect(result.package).toBe('evil-pkg');
    expect(result.origin).toBe('dependency');
  });

  it('does not let an eval frame pass a call off as application code', () => {
    const stack = [
      'Error',
      '    at readFileSync (node:fs:100:5)',
      '    at eval (/proj/app-legit.js:1:1)',
      '    at steal (/proj/node_modules/evil-pkg/index.js:10:3)',
    ].join('\n');

    const result = attributor.attribute(stack);
    expect(result.package).toBe('evil-pkg');
    expect(result.origin).toBe('dependency');
  });

  it('falls back to unknown when an eval frame is all there is', () => {
    // Nothing left to attribute to: held to the default policy bucket rather
    // than trusted as the application.
    const stack = ['Error', '    at eval (/proj/app.js:1:1)'].join('\n');
    const result = attributor.attribute(stack);
    expect(result.package).toBeNull();
    expect(result.origin).toBe('unknown');
  });

  it('handles scoped packages', () => {
    const stack = '    at x (/p/node_modules/@acme/tool/lib.js:2:2)';
    expect(attributor.attribute(stack).package).toBe('@acme/tool');
  });

  it('returns the deepest package for nested node_modules', () => {
    const stack = '    at y (/p/node_modules/a/node_modules/b/index.js:1:1)';
    expect(attributor.attribute(stack).package).toBe('b');
  });

  it('returns application origin for app code with no node_modules frame', () => {
    const stack = ['Error', '    at main (/proj/app.js:1:1)'].join('\n');
    const result = attributor.attribute(stack);
    expect(result.package).toBeNull();
    expect(result.origin).toBe('application');
    expect(result.frames).toEqual(['at main (/proj/app.js:1:1)']);
  });

  it('normalises Windows backslash paths', () => {
    const stack = '    at z (C:\\proj\\node_modules\\win-pkg\\index.js:1:1)';
    expect(attributor.attribute(stack).package).toBe('win-pkg');
  });

  it('ignores malformed scoped paths', () => {
    const stack = '    at q (/p/node_modules/@scope)';
    const result = attributor.attribute(stack);
    expect(result.package).toBeNull();
    // Under node_modules but unattributable — emphatically not "your code".
    expect(result.origin).toBe('unknown');
  });

  it('respects maxFrames', () => {
    const limited = new StackAttributor({ maxFrames: 2, selfRoot: null });
    const stack = [
      '    at a (/p/node_modules/x/i.js:1:1)',
      '    at b (/p/app1.js:1:1)',
      '    at c (/p/app2.js:1:1)',
      '    at d (/p/app3.js:1:1)',
    ].join('\n');
    expect(limited.attribute(stack).frames).toHaveLength(2);
  });

  it('keeps looking for an owner past maxFrames', () => {
    const limited = new StackAttributor({ maxFrames: 1, selfRoot: null });
    const stack = [
      '    at a (node:internal/timers:1:1)',
      '    at b (node:internal/process:1:1)',
      '    at c (/p/node_modules/deep-pkg/i.js:1:1)',
    ].join('\n');
    const result = limited.attribute(stack);
    expect(result.package).toBe('deep-pkg');
    expect(result.frames).toHaveLength(1);
  });

  it('honours a custom self package name', () => {
    const custom = new StackAttributor({ selfPackage: 'my-guard', selfRoot: null });
    const stack = [
      '    at g (/p/node_modules/my-guard/index.js:1:1)',
      '    at h (/p/node_modules/real-pkg/index.js:1:1)',
    ].join('\n');
    expect(custom.attribute(stack).package).toBe('real-pkg');
  });
});

describe('StackAttributor — unknown origin', () => {
  // This is the shape of a deferred, detached call: the scheduler's frames are
  // gone and only the runtime is left holding the bag.
  it('reports unknown when only runtime internals are on the stack', () => {
    const stack = [
      'Error',
      '    at listOnTimeout (node:internal/timers:581:17)',
      '    at process.processTimers (node:internal/timers:519:7)',
    ].join('\n');
    const result = attributor.attribute(stack);
    expect(result.package).toBeNull();
    expect(result.origin).toBe('unknown');
  });

  it('reports unknown for native and anonymous frames', () => {
    const stack = ['    at Array.forEach (<anonymous>)', '    at native'].join('\n');
    expect(attributor.attribute(stack).origin).toBe('unknown');
  });

  it('reports unknown for an empty stack', () => {
    expect(attributor.attribute('').origin).toBe('unknown');
  });

  it('treats dephawk’s own directory as self, not as application code', () => {
    const rooted = new StackAttributor({ selfRoot: '/opt/dephawk/dist/' });
    const stack = [
      'Error',
      '    at wrapped (/opt/dephawk/dist/register.js:120:9)',
      '    at listOnTimeout (node:internal/timers:581:17)',
    ].join('\n');
    const result = rooted.attribute(stack);
    expect(result.origin).toBe('unknown');
    expect(result.frames).toEqual(['at listOnTimeout (node:internal/timers:581:17)']);
  });

  it('finds the file inside an eval frame', () => {
    const stack =
      '    at eval (eval at run (/p/node_modules/staged/i.js:3:9), <anonymous>:1:1)';
    expect(attributor.attribute(stack).package).toBe('staged');
  });

  it('recognises a bare filename location as application code', () => {
    expect(attributor.attribute('    at run (bundle.js:1:1)').origin).toBe('application');
  });

  it('does not launder a data: URL module into application code', () => {
    // `import('data:text/javascript,…')` runs a module whose frames read
    // `data:text/javascript,…`. The `/` in the MIME type used to satisfy
    // isSourceLocation, so a deferred call from inside it — with the importer
    // frame gone — classified as `application` and was allowed under --enforce.
    const stack =
      'Error\n' +
      "    at evil (data:text/javascript,%0Afs.readFileSync('/etc/passwd'):3:15)\n" +
      '    at listOnTimeout (node:internal/timers:594:17)';
    const result = attributor.attribute(stack);
    expect(result.origin).toBe('unknown'); // not 'application'
    expect(result.package).toBeNull();
  });

  it('does not let a data: URL body forge a node_modules frame', () => {
    // The data body is attacker-controlled text and can contain the literal
    // `node_modules/<pkg>/` — it must not be parsed as a real dependency frame.
    const stack =
      'Error\n' +
      '    at evil (data:text/javascript,/*node_modules/innocent/index.js*/x:1:1)\n' +
      '    at listOnTimeout (node:internal/timers:594:17)';
    const result = attributor.attribute(stack);
    expect(result.origin).toBe('unknown');
    expect(result.package).toBeNull();
  });

  it('never trusts an eval-defined frame as application code', () => {
    // `eval("//# sourceURL=/app/x.js\nfunction steal(){…}")` then calling steal
    // used to classify as application (the forged /app/x.js) and be allowed.
    // captureStack now marks eval frames with the EVAL_FRAME sentinel; even with
    // a genuine application frame below, the call is `unknown` (default bucket).
    const stack = `Error\n    at steal (${EVAL_FRAME})\n    at run (/app/index.js:1:1)`;
    const result = attributor.attribute(stack);
    expect(result.origin).toBe('unknown');
    expect(result.package).toBeNull();
  });

  it('still attributes an eval frame to a real dependency below it', () => {
    // A dependency that legitimately uses eval is named by its own module frame.
    const stack = `Error\n    at gen (${EVAL_FRAME})\n    at x (/app/node_modules/tpl/i.js:2:3)`;
    const result = attributor.attribute(stack);
    expect(result.origin).toBe('dependency');
    expect(result.package).toBe('tpl');
  });

  it('still treats a file: URL module as real source', () => {
    // file: URLs are genuine on-disk modules — ESM app code shows up this way.
    expect(attributor.attribute('    at run (file:///app/index.js:1:1)').origin).toBe(
      'application',
    );
    expect(
      attributor.attribute('    at x (file:///app/node_modules/dep/i.js:1:1)').package,
    ).toBe('dep');
  });
});
