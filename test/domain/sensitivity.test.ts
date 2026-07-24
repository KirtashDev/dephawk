import { describe, it, expect } from 'vitest';
import { isSensitivePath, isSensitiveEnv } from '../../src/domain/sensitivity.js';

describe('isSensitivePath', () => {
  it.each([
    '/home/alice/.ssh/id_rsa',
    '/Users/bob/.aws/credentials',
    '/home/alice/.gnupg/secring.gpg',
    '/home/alice/.npmrc',
    '/srv/app/.env',
    '/etc/passwd',
    '/etc/shadow',
    '/home/alice/.config/gcloud/credentials.db',
    '/home/alice/.kube/config',
  ])('flags sensitive path %s', (path) => {
    expect(isSensitivePath(path)).toBe(true);
  });

  it('flags bare sensitive basenames anywhere', () => {
    expect(isSensitivePath('project/config/id_ed25519')).toBe(true);
    expect(isSensitivePath('.npmrc')).toBe(true);
  });

  it('normalises windows separators', () => {
    expect(isSensitivePath('C:\\Users\\bob\\.ssh\\id_rsa')).toBe(true);
  });

  it.each([
    '/home/alice/project/index.js',
    '/tmp/cache/data.json',
    '/usr/lib/node_modules/left-pad/index.js',
    '/etc/hosts',
  ])('does not flag mundane path %s', (path) => {
    expect(isSensitivePath(path)).toBe(false);
  });
});

describe('isSensitiveEnv', () => {
  it.each([
    'NPM_TOKEN',
    'AWS_SECRET_ACCESS_KEY',
    'GITHUB_TOKEN',
    'MY_API_KEY',
    'DATABASE_PASSWORD',
    'SESSION_SECRET',
    'PRIVATE_KEY',
  ])('flags secret var %s', (name) => {
    expect(isSensitiveEnv(name)).toBe(true);
  });

  it.each(['NODE_ENV', 'PATH', 'HOME', 'LANG', 'PWD'])(
    'does not flag mundane var %s',
    (name) => {
      expect(isSensitiveEnv(name)).toBe(false);
    },
  );
});
