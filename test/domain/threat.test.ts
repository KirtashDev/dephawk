import { describe, it, expect } from 'vitest';
import {
  detectExfilChains,
  detectTechnique,
  isCiWorkflowPath,
  isCloudMetadataHost,
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
  ])('normalizes %s → %s', (input, expected) => {
    expect(normalizeIpv4(input)).toBe(expected);
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

describe('isCiWorkflowPath — .github/workflows persistence', () => {
  it.each([
    '/repo/.github/workflows/shai-hulud.yml',
    '/repo/.github/workflows/ci.yaml',
    '.github/workflows/deploy.yml',
    'C:\\proj\\.github\\workflows\\x.yml',
  ])('flags %s', (path) => {
    expect(isCiWorkflowPath(path)).toBe(true);
  });

  it.each([
    '/repo/.github/dependabot.yml', // not under workflows/
    '/repo/.github/workflows/', // the directory, no file
    '/repo/src/workflows/x.yml', // not under .github
    '/repo/.github/workflows/notes.txt', // not a yaml file
  ])('does not flag %s', (path) => {
    expect(isCiWorkflowPath(path)).toBe(false);
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
