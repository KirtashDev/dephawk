import { describe, it, expect } from 'vitest';
import { isCrossPackageWrite, packageOwningPath } from '../../src/domain/package-dir.js';

describe('packageOwningPath', () => {
  it.each([
    ['/proj/node_modules/lodash/index.js', 'lodash'],
    ['/proj/node_modules/@acme/tool/lib/x.js', '@acme/tool'],
    // The deepest install wins, matching how the stack attributor names a frame.
    ['/proj/node_modules/a/node_modules/b/index.js', 'b'],
    ['C:\\proj\\node_modules\\lodash\\index.js', 'lodash'],
  ])('%s belongs to %s', (path, owner) => {
    expect(packageOwningPath(path)).toBe(owner);
  });

  it.each([
    '/proj/src/index.js',
    '/proj/app.js',
    // Directly inside node_modules, not inside a package: the installer's own
    // bookkeeping, owned by nobody.
    '/proj/node_modules/.package-lock.json',
    '/proj/node_modules/@acme',
  ])('%s has no owning package', (path) => {
    expect(packageOwningPath(path)).toBeNull();
  });
});

describe('isCrossPackageWrite', () => {
  it('is true when one package writes into another', () => {
    expect(isCrossPackageWrite('evil', 'innocent')).toBe(true);
  });

  it('is false for a package writing inside its own directory', () => {
    // Caches, compiled output and downloaded binaries all do this.
    expect(isCrossPackageWrite('sharp', 'sharp')).toBe(false);
  });

  it('is false when there is no owner, or no identified writer', () => {
    expect(isCrossPackageWrite('evil', null)).toBe(false);
    expect(isCrossPackageWrite(null, 'innocent')).toBe(false);
  });
});
