import { describe, it, expect } from 'vitest';
import { createStyler, shouldColor } from '../../../src/adapters/reporting/ansi.js';

const ESC = String.fromCharCode(27);

describe('createStyler', () => {
  it('wraps text in ANSI codes when enabled', () => {
    expect(createStyler(true)('red', 'hi')).toBe(`${ESC}[31mhi${ESC}[0m`);
  });

  it('returns plain text when disabled', () => {
    expect(createStyler(false)('red', 'hi')).toBe('hi');
  });
});

describe('shouldColor', () => {
  it('disables colour when NO_COLOR is set', () => {
    expect(shouldColor({ NO_COLOR: '1' }, true)).toBe(false);
  });

  it('forces colour when FORCE_COLOR is set (and non-zero)', () => {
    expect(shouldColor({ FORCE_COLOR: '1' }, false)).toBe(true);
    expect(shouldColor({ FORCE_COLOR: '0' }, false)).toBe(false);
  });

  it('falls back to TTY-ness', () => {
    expect(shouldColor({}, true)).toBe(true);
    expect(shouldColor({}, false)).toBe(false);
  });
});
