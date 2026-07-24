/** Minimal ANSI styling with zero dependencies. */
const CODES = {
  reset: 0,
  bold: 1,
  dim: 2,
  red: 31,
  green: 32,
  yellow: 33,
  cyan: 36,
  gray: 90,
} as const;

export type StyleName = keyof typeof CODES;

/** A styler that wraps text in ANSI codes, or returns it untouched when disabled. */
export type Styler = (name: StyleName, text: string) => string;

export function createStyler(enabled: boolean): Styler {
  if (!enabled) {
    return (_name, text) => text;
  }
  return (name, text) => `[${CODES[name]}m${text}[${CODES.reset}m`;
}

/**
 * Decide whether to emit colour: honour NO_COLOR, FORCE_COLOR, and TTY-ness.
 * Pure given its inputs so it can be unit-tested.
 */
export function shouldColor(
  env: Record<string, string | undefined>,
  isTTY: boolean,
): boolean {
  if (env['NO_COLOR'] !== undefined) {
    return false;
  }
  if (env['FORCE_COLOR'] !== undefined && env['FORCE_COLOR'] !== '0') {
    return true;
  }
  return isTTY;
}
