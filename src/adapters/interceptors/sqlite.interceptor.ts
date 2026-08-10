import { isSensitivePath } from '../../domain/sensitivity.js';
import { resolve } from 'node:path';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  loadBuiltin,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
} from './support.js';

/**
 * Intercepts `node:sqlite` (`DatabaseSync`), which opens a database file through
 * its own C++ binding — never through the `fs` module dephawk patches.
 *
 * This is the exact move the 2025-26 browser-credential stealers make:
 * Chrome/Brave/Edge keep saved passwords and cookies in SQLite files
 * (`Login Data`, `Cookies`, `Web Data`), and `new DatabaseSync('…/Login Data')`
 * reads them with a `SELECT`. dephawk already treats those paths as sensitive,
 * but the read went straight past the filesystem interceptor. Reproduced: a
 * dependency opened a `Login Data` database and read a password under
 * `--enforce` with a deny-by-default policy, invisible in the report.
 *
 * Opening a database at a sensitive path is recorded as `fs.read` with the file
 * path as the detail, so it is gated by exactly the same sensitivity rules and
 * per-package `fs.read` allowlist as a plain read. `:memory:` and other
 * non-file locations are ignored. Loading a SQLite *extension* runs native code
 * outside the JavaScript surface, like a native addon, so it is recorded as
 * `process.native` and denied by default.
 *
 * `node:sqlite` is experimental and absent before Node 22.5; if it cannot be
 * loaded the interceptor installs nothing. Its load emits a one-time
 * `ExperimentalWarning`, which is suppressed here so merely running dephawk on a
 * project that never touches SQLite does not print it.
 */
export class SqliteInterceptor implements CapabilityInterceptor {
  readonly name = 'sqlite';

  install(record: RecordFn): Disposable {
    const sqlite = loadSqlite();
    if (sqlite === null) {
      return restorer([]);
    }

    const restores: (() => void)[] = [];

    // The constructor opens the file (unless `{ open: false }`). A subclass so
    // `instanceof`/`prototype` keep working, deciding before `super()`.
    const Original = sqlite['DatabaseSync'];
    if (typeof Original === 'function') {
      const Base = Original as unknown as new (...args: unknown[]) => object;
      class WatchedDatabase extends Base {
        constructor(...args: unknown[]) {
          checkOpen(record, args[0]);
          super(...args);
        }
      }
      Object.defineProperty(WatchedDatabase, 'name', { value: 'DatabaseSync' });
      sqlite['DatabaseSync'] = WatchedDatabase;
      restores.push(() => {
        sqlite['DatabaseSync'] = Original;
      });

      // `{ open: false }` defers the file access to `.open()`.
      const proto = prototypeOf(Original);
      if (proto) {
        const restore = patchMethod(
          proto,
          'open',
          (original) =>
            function (this: { location?: () => unknown }, ...args: unknown[]): unknown {
              const location =
                typeof this.location === 'function' ? this.location() : undefined;
              checkOpen(record, location);
              return (original as (...a: unknown[]) => unknown).apply(this, args);
            },
        );
        if (restore) {
          restores.push(restore);
        }

        // Loading a SQLite extension maps native code into the process.
        const extRestore = patchMethod(
          proto,
          'loadExtension',
          (original) =>
            function (this: unknown, ...args: unknown[]): unknown {
              const path = typeof args[0] === 'string' ? args[0] : 'unknown';
              const decision = report(
                record,
                'process.native',
                `sqlite extension ${path}`,
              );
              if (!decision.allow) {
                throw blockedError(`SQLite extension load of ${path}`, decision.reason);
              }
              return (original as (...a: unknown[]) => unknown).apply(this, args);
            },
        );
        if (extRestore) {
          restores.push(extRestore);
        }
      }
    }

    return restorer(restores);
  }
}

/** Report opening `location` as an `fs.read`, and throw when it is refused. */
function checkOpen(record: RecordFn, location: unknown): void {
  if (typeof location !== 'string' || location.length === 0) {
    return; // a Buffer/URL location is rare; :memory: and named DBs are not files
  }
  if (location === ':memory:' || location.startsWith('file::memory:')) {
    return;
  }
  const path = resolve(location);
  if (!isSensitivePath(path)) {
    return; // mundane database: no event, matching the fs interceptor
  }
  const decision = report(record, 'fs.read', path);
  if (!decision.allow) {
    throw blockedError(`fs.read of ${path}`, decision.reason);
  }
}

/**
 * Load `node:sqlite` if this runtime has it, with its `ExperimentalWarning`
 * suppressed for the duration of the load. Returns null when it is unavailable.
 */
function loadSqlite(): Record<string, unknown> | null {
  const saved = process.emitWarning;
  try {
    process.emitWarning = ((warning: unknown, ...rest: unknown[]): void => {
      if (String(warning).includes('SQLite')) {
        return;
      }
      (saved as (w: unknown, ...r: unknown[]) => void)(warning, ...rest);
    }) as typeof process.emitWarning;
    return loadBuiltin<Record<string, unknown>>('node:sqlite');
  } catch {
    return null;
  } finally {
    process.emitWarning = saved;
  }
}
