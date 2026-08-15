import { describe, it, expect } from 'vitest';
import {
  isSensitivePath,
  isSensitiveEnv,
  isPersistenceTarget,
  looksLikeSecretValue,
} from '../../src/domain/sensitivity.js';

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

describe('isSensitivePath — the directory itself, not just its contents', () => {
  // Listing `~/.ssh` names every key and every host without reading a byte.
  // Until the rules matched a bare directory, that recon was invisible.
  it.each([
    '/home/alice/.ssh',
    '/home/alice/.ssh/',
    '/Users/bob/.aws',
    '/Users/bob/Library/Keychains',
    'C:\\Users\\bob\\.gnupg',
  ])('flags the sensitive directory %s', (path) => {
    expect(isSensitivePath(path)).toBe(true);
  });

  it('does not flag a file that merely ends in a sensitive directory name', () => {
    expect(isSensitivePath('/home/alice/notes.ssh')).toBe(false);
    expect(isSensitivePath('/home/alice/backup-aws')).toBe(false);
  });
});

describe('isSensitivePath — 2024-25 threat coverage', () => {
  it.each([
    // Plaintext git credentials, and the GitHub CLI's token.
    '/home/alice/.git-credentials',
    '/home/alice/.config/gh/hosts.yml',
    // Key material by extension.
    '/home/alice/certs/server.pem',
    '/home/alice/certs/server.key',
    '/srv/app/keystore.p12',
    '/home/alice/Passwords.kdbx',
    // OS credential stores.
    '/Users/bob/Library/Keychains/login.keychain-db',
    '/home/alice/.local/share/keyrings/login.keyring',
    'C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21\\masterkey',
    // Crypto wallets — the payload of choice in recent npm compromises.
    '/home/alice/.ethereum/keystore/UTC--2025-01-01--abc',
    '/home/alice/.electrum/wallets/default_wallet',
    '/home/alice/.config/solana/id.json',
    '/home/alice/.near-credentials/mainnet/alice.json',
    '/home/alice/.bitcoin/wallet.dat',
    '/Users/bob/Library/Application Support/exodus/exodus.wallet/seed.seco',
    '/Users/bob/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log',
    // Cloud and registry credentials.
    '/home/alice/.azure/accessTokens.json',
    '/home/alice/.pypirc',
    // Every environment variable in one read, bypassing the env interceptor.
    '/proc/self/environ',
    '/proc/1417/environ',
    // Per-environment dotenv files, not just `.env`.
    '/srv/app/.env.production',
  ])('flags %s', (path) => {
    expect(isSensitivePath(path)).toBe(true);
  });

  it('matches case-insensitively, so casing is not a bypass', () => {
    expect(isSensitivePath('/Users/bob/library/keychains/login.keychain-db')).toBe(true);
    expect(isSensitivePath('/home/alice/.SSH/id_rsa')).toBe(true);
  });

  it('does not treat key material inside node_modules as your secret', () => {
    // A `.pem` shipped with a package is a CA bundle or a test fixture. Flagging
    // those would make every TLS-using dependency noisy enough to be ignored.
    expect(isSensitivePath('/srv/app/node_modules/agent/test/fixtures/server.pem')).toBe(
      false,
    );
    // Location-based rules still bite there: no package ships your SSH key.
    expect(isSensitivePath('/srv/app/node_modules/evil/.ssh/id_rsa')).toBe(true);
  });

  it.each([
    '/home/alice/project/.environment',
    '/home/alice/project/environ',
    '/home/alice/project/public.crt',
    '/home/alice/project/monkey.json',
  ])('still does not flag mundane path %s', (path) => {
    expect(isSensitivePath(path)).toBe(false);
  });
});

describe('isSensitivePath — browser credential theft (the 2025-26 npm stealers)', () => {
  it.each([
    // Chromium saved-password DB and the key that decrypts it — a stealer needs
    // both — whatever the OS or profile the path lands on.
    '/Users/bob/Library/Application Support/Google/Chrome/Default/Login Data',
    '/home/alice/.config/google-chrome/Default/Local State',
    '/Users/bob/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data',
    'C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data',
    // Firefox equivalents.
    '/home/alice/.mozilla/firefox/abc.default-release/logins.json',
    '/home/alice/.mozilla/firefox/abc.default-release/key4.db',
    '/home/alice/.mozilla/firefox/abc.default-release/cookies.sqlite',
    // Listing the profile directory is recon in its own right.
    '/home/alice/.config/google-chrome',
    '/home/alice/.mozilla/firefox',
    '/Users/bob/Library/Application Support/Google/Chrome',
  ])('flags %s', (path) => {
    expect(isSensitivePath(path)).toBe(true);
  });

  it('does not flag a mundane file that merely says state or data', () => {
    expect(isSensitivePath('/home/alice/project/global state.json')).toBe(false);
    expect(isSensitivePath('/home/alice/project/user data.txt')).toBe(false);
  });
});

describe('isPersistenceTarget — shell startup files (write-side persistence)', () => {
  it.each([
    '/home/alice/.bashrc',
    '/home/alice/.bash_profile',
    '/home/alice/.profile',
    '/Users/bob/.zshrc',
    '/Users/bob/.zshenv',
    '/home/alice/.config/fish/config.fish',
    'C:\\Users\\bob\\.zshrc',
  ])('flags a write to %s', (path) => {
    expect(isPersistenceTarget(path)).toBe(true);
  });

  it('does not flag mundane files that merely resemble a shell rc', () => {
    expect(isPersistenceTarget('/home/alice/project/bashrc.md')).toBe(false);
    expect(isPersistenceTarget('/home/alice/project/config.fish.txt')).toBe(false);
    expect(isPersistenceTarget('/home/alice/project/notes.txt')).toBe(false);
  });
});

describe('isSensitivePath — /proc and more credential files', () => {
  it.each([
    '/proc/self/environ',
    '/proc/1234/environ',
    '/proc/1234/task/1250/environ', // thread form
    '/proc/self/mem',
    '/proc/self/maps',
    '/proc/1234/pagemap',
    '/private/etc/passwd', // macOS canonical form of /etc/passwd
    '/private/etc/shadow',
    '/home/alice/.pgpass',
    '/home/alice/.vault-token',
    '/home/alice/.terraform.d/credentials.tfrc.json',
    '/home/alice/.terraform.d', // listing the store is recon too
  ])('flags %s', (path) => {
    expect(isSensitivePath(path)).toBe(true);
  });

  it('does not flag mundane /proc files or lookalikes', () => {
    expect(isSensitivePath('/proc/cpuinfo')).toBe(false);
    expect(isSensitivePath('/proc/self/status')).toBe(false);
    expect(isSensitivePath('/home/alice/project/memory.js')).toBe(false);
    expect(isSensitivePath('/home/alice/proc/app/mem')).toBe(false); // not under /proc
  });
});

describe('isSensitivePath — container & Kubernetes secret mounts (2026 worms)', () => {
  it.each([
    // The keyv worm and the Red Hat Cloud Services / Miasma campaigns read the
    // service-account token, then query the cluster API for every namespace secret.
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
    '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
    '/var/run/secrets/kubernetes.io/serviceaccount', // listing the dir is recon too
    '/run/secrets/kubernetes.io/serviceaccount/token', // /var/run -> /run symlink form
    // Docker / Swarm / BuildKit mount secrets under /run/secrets.
    '/run/secrets/db_password',
    '/run/secrets/npm_token',
    '/run/secrets',
  ])('flags %s', (path) => {
    expect(isSensitivePath(path)).toBe(true);
  });

  it('does not flag lookalike paths outside the secret mount', () => {
    expect(isSensitivePath('/home/alice/project/run/README.md')).toBe(false);
    expect(isSensitivePath('/srv/secrets-manager/config.json')).toBe(false);
  });
});

describe('looksLikeSecretValue — a credential hiding under an innocuous name', () => {
  it.each([
    'postgres://user:secretpass@db.example.com:5432/app',
    'redis://default:hunter2@cache:6379',
    'mongodb+srv://admin:p@ss@cluster0.mongodb.net',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----',
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n',
  ])('flags a credential value', (value) => {
    expect(looksLikeSecretValue(value)).toBe(true);
  });

  it.each([
    'production',
    '/usr/local/bin:/usr/bin',
    'https://cdn.example.com/assets', // a URL, but no embedded user:pass@
    'https://user@host.com/path', // a user, but no password
    'postgres://localhost:5432/app', // no credentials
    '', // empty
  ])('does not flag a mundane value', (value) => {
    expect(looksLikeSecretValue(value)).toBe(false);
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
    'MYSQL_PWD', // the MySQL client password variable
    'DB_PWD',
  ])('flags secret var %s', (name) => {
    expect(isSensitiveEnv(name)).toBe(true);
  });

  it.each([
    'NODE_ENV',
    'PATH',
    'HOME',
    'LANG',
    'PWD',
    // False friends that must NOT be flagged:
    'NODE_TLS_REJECT_UNAUTHORIZED', // contains "AUTH"
    'MONKEY', // contains "KEY"
    'KEYBOARD_LAYOUT', // starts with "KEY" but not a delimited word
    'PWD', // the working-directory variable, not a password
    'OLDPWD', // ditto — no delimiter before PWD
  ])('does not flag mundane var %s', (name) => {
    expect(isSensitiveEnv(name)).toBe(false);
  });
});
