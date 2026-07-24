import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { HtmlReporter } from '../../../src/adapters/reporting/html-reporter.js';
import type { HtmlWriter } from '../../../src/adapters/reporting/html-reporter.js';
import { mixed } from './events.js';

function fakeWriter() {
  const state: { dir?: string; path?: string; data?: string } = {};
  const writer: HtmlWriter = {
    async mkdir(dir) {
      state.dir = dir;
    },
    async writeFile(path, data) {
      state.path = path;
      state.data = data;
    },
  };
  return { writer, state };
}

describe('HtmlReporter', () => {
  it('writes the report to the resolved output path', async () => {
    const { writer, state } = fakeWriter();
    const logs: string[] = [];
    const reporter = new HtmlReporter({
      outputPath: '.dephawk/report.html',
      writer,
      now: () => new Date('2026-07-24T00:00:00.000Z'),
      log: (m) => logs.push(m),
    });

    await reporter.report(mixed);

    expect(state.path).toBe(resolve('.dephawk/report.html'));
    expect(state.dir).toBe(resolve('.dephawk'));
    expect(state.data).toContain('dephawk report');
    expect(state.data).toContain('2026-07-24T00:00:00.000Z');
    expect(logs[0]).toContain(resolve('.dephawk/report.html'));
  });
});
