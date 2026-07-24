import { describe, it, expect } from 'vitest';
import { renderHtmlReport } from '../../../src/adapters/reporting/html-format.js';
import { ev, mixed } from './events.js';

const meta = { generatedAt: '2026-07-24T00:00:00.000Z' };

describe('renderHtmlReport', () => {
  it('produces a self-contained HTML document', () => {
    const html = renderHtmlReport(mixed, meta);
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('<style>');
    expect(html).not.toMatch(/<script\b/); // no scripts
    expect(html).not.toContain('http://'); // no external asset URLs
    expect(html).toContain('dephawk report');
    expect(html).toContain('2 packages touched something sensitive');
    expect(html).toContain('evil-pkg');
  });

  it('includes the honest threat-model footer', () => {
    expect(renderHtmlReport(mixed, meta)).toContain('not an unbreakable sandbox');
  });

  it('escapes HTML in package names and details (no injection)', () => {
    const nasty = ev({
      package: '<img src=x onerror=alert(1)>',
      detail: '"><script>evil()</script>',
      allowed: false,
    });
    const html = renderHtmlReport([nasty], meta);
    expect(html).not.toContain('<script>evil');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;script&gt;');
  });

  it('celebrates when nothing sensitive happened', () => {
    const html = renderHtmlReport([ev(), ev()], meta);
    expect(html).toContain('No packages tried anything sensitive');
  });
});
