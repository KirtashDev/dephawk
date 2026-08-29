import { describe, it, expect } from 'vitest';
import {
  isInsideDirectory,
  packageNameOf,
} from '../../src/composition/examine-package.js';

describe('packageNameOf — bare name from an install spec', () => {
  it.each([
    ['lodash', 'lodash'],
    ['lodash@4.17.21', 'lodash'],
    ['lodash@latest', 'lodash'],
    ['@scope/pkg', '@scope/pkg'],
    ['@scope/pkg@1.2.3', '@scope/pkg'],
    ['@scope/pkg@next', '@scope/pkg'],
  ])('%s → %s', (spec, expected) => {
    expect(packageNameOf(spec)).toBe(expected);
  });
});

describe('examinePackage — sandbox filter prefix boundaries', () => {
  // The third site with the CVE-2026-58043 shape. Here the failure mode is the
  // mirror image of over-granting: a filter that swallowed a sibling directory
  // would silently *drop* real findings from the audit.
  it('drops only what is genuinely inside the throwaway sandbox', () => {
    expect(isInsideDirectory('/tmp/dephawk-x-ab12', '/tmp/dephawk-x-ab12')).toBe(true);
    expect(
      isInsideDirectory('/tmp/dephawk-x-ab12', '/tmp/dephawk-x-ab12/node_modules/p'),
    ).toBe(true);
  });

  it('keeps a name-prefix sibling, which is a real finding', () => {
    expect(
      isInsideDirectory('/tmp/dephawk-x-ab12', '/tmp/dephawk-x-ab12-evil/loot'),
    ).toBe(false);
    expect(isInsideDirectory('/tmp/dephawk-x-ab12', '/tmp/dephawk-x-ab120/loot')).toBe(
      false,
    );
  });
});
