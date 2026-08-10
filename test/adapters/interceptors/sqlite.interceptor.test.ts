import { describe, it, expect, afterEach } from 'vitest';
import { SqliteInterceptor } from '../../../src/adapters/interceptors/sqlite.interceptor.js';
import { loadBuiltin } from '../../../src/adapters/interceptors/support.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

// node:sqlite is experimental and absent before Node 22.5. Where it is missing,
// the interceptor installs nothing, and there is nothing to exercise.
interface Sqlite {
  DatabaseSync: new (
    location: string,
    options?: unknown,
  ) => {
    exec(sql: string): void;
    close(): void;
  };
}
function tryLoadSqlite(): Sqlite | null {
  const saved = process.emitWarning;
  try {
    process.emitWarning = (() => undefined) as typeof process.emitWarning;
    return loadBuiltin<Sqlite>('node:sqlite');
  } catch {
    return null;
  } finally {
    process.emitWarning = saved;
  }
}
const sqlite = tryLoadSqlite();

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

describe.skipIf(sqlite === null)('SqliteInterceptor', () => {
  const SENSITIVE = '/home/nobody/.config/google-chrome/Default/Login Data';

  it('blocks opening a database at a sensitive path, as fs.read', () => {
    const spy = recordSpy();
    spy.deny('no browser databases');
    installed = new SqliteInterceptor().install(spy.record);

    // Denied before the C++ binding ever opens the file.
    expect(() => new sqlite!.DatabaseSync(SENSITIVE)).toThrow(/dephawk: blocked/);
    expect(spy.last?.capability).toBe('fs.read');
    expect(spy.last?.detail).toContain('Login Data');
  });

  it('does not flag an in-memory database', () => {
    const spy = recordSpy();
    spy.deny();
    installed = new SqliteInterceptor().install(spy.record);

    const db = new sqlite!.DatabaseSync(':memory:');
    db.close();
    expect(spy.calls).toHaveLength(0);
  });

  it('does not flag a mundane database file', () => {
    const spy = recordSpy();
    spy.deny('would throw if reported');
    installed = new SqliteInterceptor().install(spy.record);

    const db = new sqlite!.DatabaseSync('/tmp/dephawk-mundane-test.db');
    db.close();
    expect(spy.calls).toHaveLength(0);
  });

  it('restores the original DatabaseSync on dispose', () => {
    const before = sqlite!.DatabaseSync;
    const local = new SqliteInterceptor().install(recordSpy().record);
    expect(sqlite!.DatabaseSync).not.toBe(before);
    local.dispose();
    expect(sqlite!.DatabaseSync).toBe(before);
  });
});
