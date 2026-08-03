import { describe, it, expect } from 'vitest';
import { redactSecrets } from '../../src/domain/redact.js';

describe('redactSecrets — the value goes, the name stays', () => {
  it.each([
    // A spawn's detail is the whole command line, which is where this bites.
    [
      'curl -H "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345" https://api.github.com',
      'curl -H "Authorization: Bearer ***" https://api.github.com',
    ],
    ['npm publish --token=npm_abcdefghijklmnopqrstuvwxyz', 'npm publish --token=***'],
    ['npm publish --token npm_abcdefghijklmnopqrstuvwxyz', 'npm publish --token ***'],
    ['sh -c NPM_TOKEN=abc123 npm publish', 'sh -c NPM_TOKEN=*** npm publish'],
    ['mysql -u root --password hunter2', 'mysql -u root --password ***'],
    // A URL is a net.connect detail, and query strings carry credentials.
    [
      'https://collector.example.com/in?access_token=s3cr3t&run=12',
      'https://collector.example.com/in?access_token=***&run=12',
    ],
    [
      'https://alice:hunter2@internal.example.com/repo.git',
      'https://alice:***@internal.example.com/repo.git',
    ],
  ])('redacts %s', (input, expected) => {
    expect(redactSecrets(input)).toBe(expected);
  });

  it.each([
    // Self-identifying shapes, even with no name in front of them. The prefix
    // survives: knowing which kind of token leaked is the actionable part.
    ['echo ghp_abcdefghijklmnopqrstuvwxyz012345', 'echo ghp_***'],
    ['echo github_pat_11ABCDEFGHIJKLMNOPQRST_abcdefgh', 'echo github_pat_***'],
    ['echo glpat-abcdefghijklmnopqrst', 'echo glpat-***'],
    ['echo xoxb-1234567890-abcdefghij', 'echo xoxb-***'],
    ['echo sk-abcdefghijklmnopqrstuvwx', 'echo sk-***'],
    ['aws configure set key AKIAIOSFODNN7EXAMPLE', 'aws configure set key AKIA***'],
    [
      'node -e fetch(x,{headers:{a:"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"}})',
      'node -e fetch(x,{headers:{a:"eyJ***"}})',
    ],
  ])('redacts the bare token in %s', (input, expected) => {
    expect(redactSecrets(input)).toBe(expected);
  });
});

describe('redactSecrets — leaves everything else legible', () => {
  // The failure mode that matters: a report you cannot act on. These are the
  // strings dephawk records constantly.
  it.each([
    '/Users/alice/.ssh/id_rsa',
    '/home/alice/.aws',
    'npm ci',
    'node examples/demo/index.js',
    'node payload.js [dephawk re-attached: DEPHAWK_SINK, NODE_OPTIONS]',
    'NODE_ENV=production npm run build',
    'https://collector.dephawk-demo.invalid/exfil',
    'collector.dephawk-demo.invalid:443',
    'dephawk run --fail-on violation --sarif dephawk.sarif npm test',
    'node -e console.log(1)',
    'sh -c "make -j4"',
    'git clone https://github.com/KirtashDev/dephawk.git',
  ])('leaves %s untouched', (input) => {
    expect(redactSecrets(input)).toBe(input);
  });

  it('does not mistake a short flag value for a secret', () => {
    expect(redactSecrets('tar -x -f archive.tgz')).toBe('tar -x -f archive.tgz');
  });

  it('keeps the rest of a command line around a redacted value', () => {
    expect(redactSecrets('deploy --region eu-west-1 --api-key=abcdef --dry-run')).toBe(
      'deploy --region eu-west-1 --api-key=*** --dry-run',
    );
  });
});
