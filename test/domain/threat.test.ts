import { describe, it, expect } from 'vitest';
import {
  detectExfilChains,
  detectTechnique,
  isCiWorkflowPath,
  isCloudMetadataHost,
  isGitHookPath,
  isRegistryPublish,
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
