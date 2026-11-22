import { describe, it, expect } from 'vitest';
import { runtimeLoaderEnv, withDenoPreload } from '../../src/composition/runtime-env.js';

const URL_ = 'file:///opt/dephawk/dist/register.js';

describe('runtimeLoaderEnv', () => {
  it('attaches Node and Bun, and turns JSC tail calls off', () => {
    expect(runtimeLoaderEnv({}, URL_)).toEqual({
      NODE_OPTIONS: `--import ${URL_}`,
      BUN_OPTIONS: `--preload ${URL_}`,
      BUN_JSC_useTailCalls: 'false',
    });
  });

  it('keeps existing options and does not repeat itself', () => {
    const once = runtimeLoaderEnv(
      { NODE_OPTIONS: '--max-old-space-size=4096', BUN_OPTIONS: '--smol' },
      URL_,
    );
    expect(once['NODE_OPTIONS']).toBe(`--max-old-space-size=4096 --import ${URL_}`);
    expect(once['BUN_OPTIONS']).toBe(`--smol --preload ${URL_}`);
    expect(runtimeLoaderEnv(once, URL_)).toEqual(once);
  });
});

describe('withDenoPreload', () => {
  it.each([
    [
      ['run', '-A', 'app.ts'],
      ['run', '--preload', URL_, '-A', 'app.ts'],
    ],
    [['test'], ['test', '--preload', URL_]],
    [
      ['serve', 'main.ts'],
      ['serve', '--preload', URL_, 'main.ts'],
    ],
  ])('inserts --preload after the subcommand: %j', (args, expected) => {
    expect(withDenoPreload('deno', args, URL_)).toEqual(expected);
    expect(withDenoPreload('/usr/local/bin/deno', args, URL_)).toEqual(expected);
    expect(withDenoPreload('C:\\deno\\deno.exe', args, URL_)).toEqual(expected);
  });

  it('leaves everything else alone', () => {
    expect(withDenoPreload('node', ['run', 'x'], URL_)).toEqual(['run', 'x']);
    expect(withDenoPreload('deno', ['fmt'], URL_)).toEqual(['fmt']);
    expect(withDenoPreload('deno', [], URL_)).toEqual([]);
    const already = ['run', '--preload', URL_, 'a.ts'];
    expect(withDenoPreload('deno', already, URL_)).toEqual(already);
  });
});
