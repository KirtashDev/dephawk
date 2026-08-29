import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import childProcess from 'node:child_process';
import { TECHNIQUE_GLOSS, detectTechnique } from '../../../src/domain/threat.js';
import type { Technique } from '../../../src/domain/threat.js';
import type { Capability } from '../../../src/domain/capability.js';
import { FsInterceptor } from '../../../src/adapters/interceptors/fs.interceptor.js';
import { EnvInterceptor } from '../../../src/adapters/interceptors/env.interceptor.js';
import { ChildProcessInterceptor } from '../../../src/adapters/interceptors/child-process.interceptor.js';
import type { Disposable } from '../../../src/application/ports.js';
import { recordSpy } from './spy.js';

/**
 * Every recognised technique must survive the trip from a real Node call to a
 * recorded event — not merely be recognised by `detectTechnique`.
 *
 * This exists because `service-persistence` shipped complete in the domain
 * (predicate, gloss, `detectTechnique` wired, unit tests green) and did nothing
 * end to end: the fs interceptor's own lexical pre-filter decides whether a
 * write is worth reporting at all, and it named the other persistence
 * predicates by hand, returning early on everything else. Nothing in the suite
 * asked whether a technique was actually *reachable*.
 *
 * The fixture table is typed `Record<Technique, …>`, so adding a technique to
 * the union without a fixture is a **compile error**, not a silent gap.
 */
interface Fixture {
  readonly capability: Capability;
  /** Drives the real built-in and returns the details the interceptor recorded. */
  readonly exercise: () => readonly string[];
}

let installed: Disposable | undefined;
afterEach(() => {
  installed?.dispose();
  installed = undefined;
});

/** Run a filesystem call under the real interceptor and collect what it saw. */
function throughFs(call: () => void): readonly string[] {
  const spy = recordSpy();
  spy.deny('coverage probe');
  installed = new FsInterceptor().install(spy.record);
  try {
    call();
  } catch {
    // Denied is the expected outcome; we only care what was recorded.
  }
  return spy.calls.map((c) => c.detail);
}

function throughSpawn(call: () => void): readonly string[] {
  const spy = recordSpy();
  spy.deny('coverage probe');
  installed = new ChildProcessInterceptor().install(spy.record);
  try {
    call();
  } catch {
    /* denied */
  }
  return spy.calls.map((c) => c.detail);
}

function throughEnv(call: () => void): readonly string[] {
  const spy = recordSpy();
  spy.deny('coverage probe');
  installed = new EnvInterceptor().install(spy.record);
  try {
    call();
  } catch {
    /* denied */
  }
  return spy.calls.map((c) => c.detail);
}

// Paths are fabricated and never created; the interceptors judge them lexically,
// and every call below is denied before it reaches the filesystem.
const HOME = '/home/nobody-dephawk-coverage';

const FIXTURES: Record<Technique, Fixture> = {
  'cloud-metadata': {
    capability: 'net.connect',
    // Network has no pre-filter — every connect is reported — so the domain
    // check below is the whole test for these two.
    exercise: () => ['http://169.254.169.254/latest/meta-data/'],
  },
  'dead-drop-c2': {
    capability: 'net.connect',
    exercise: () => ['https://evil.workers.dev/c2'],
  },
  'local-service-pivot': {
    capability: 'net.connect',
    exercise: () => ['127.0.0.1:6379'],
  },
  'ci-workflow-persistence': {
    capability: 'fs.write',
    exercise: () =>
      throughFs(() => fs.writeFileSync(`${HOME}/.github/workflows/ci.yml`, 'x')),
  },
  'git-hook-persistence': {
    capability: 'fs.write',
    exercise: () =>
      throughFs(() => fs.writeFileSync(`${HOME}/.git/hooks/pre-commit`, 'x')),
  },
  'editor-hook-persistence': {
    capability: 'fs.write',
    exercise: () => throughFs(() => fs.writeFileSync(`${HOME}/.vscode/tasks.json`, 'x')),
  },
  'service-persistence': {
    capability: 'fs.write',
    exercise: () =>
      throughFs(() =>
        fs.writeFileSync(`${HOME}/.config/systemd/user/beacon.service`, 'x'),
      ),
  },
  'manifest-tamper': {
    capability: 'fs.write',
    exercise: () =>
      throughFs(() => fs.writeFileSync(`${HOME}/node_modules/victim/package.json`, 'x')),
  },
  'ai-credential-theft': {
    capability: 'fs.read',
    exercise: () => throughFs(() => fs.readFileSync(`${HOME}/.claude/.credentials.json`)),
  },
  'registry-publish': {
    capability: 'process.spawn',
    exercise: () => throughSpawn(() => childProcess.spawnSync('npm', ['publish'])),
  },
  'alt-runtime-escape': {
    capability: 'process.spawn',
    exercise: () =>
      throughSpawn(() => childProcess.spawnSync('./.cache/bun', ['install'])),
  },
  'detached-process': {
    capability: 'process.spawn',
    exercise: () =>
      // `spawn`, not `spawnSync`: `detached` is not part of the sync options.
      // The call is denied before a process starts.
      throughSpawn(() =>
        childProcess.spawn('node', ['-e', '0'], { detached: true, stdio: 'ignore' }),
      ),
  },
  'tls-verification-disabled': {
    capability: 'env.write',
    exercise: () =>
      throughEnv(() => {
        process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
      }),
  },
};

describe('every recognised technique reaches a recorded event', () => {
  const entries = Object.entries(FIXTURES) as [Technique, Fixture][];

  it('has a fixture for every technique in the gloss', () => {
    expect(Object.keys(FIXTURES).sort()).toEqual(Object.keys(TECHNIQUE_GLOSS).sort());
  });

  it.each(entries)(
    '%s is reachable through the real interceptor',
    (technique, fixture) => {
      const details = fixture.exercise();
      const named = details.filter(
        (detail) =>
          detectTechnique(fixture.capability, detail, 'dependency') === technique,
      );
      expect(
        named,
        `no recorded ${fixture.capability} detail resolved to ${technique}; ` +
          `the interceptor's pre-filter probably drops it before it is ever judged. ` +
          `Recorded: ${JSON.stringify(details)}`,
      ).not.toHaveLength(0);
    },
  );
});
