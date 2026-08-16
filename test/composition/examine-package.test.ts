import { describe, it, expect } from 'vitest';
import { packageNameOf } from '../../src/composition/examine-package.js';

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
