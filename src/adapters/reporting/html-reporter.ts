import { loadBuiltin } from '../interceptors/support.js';

// `require`, not `import`: importing `node:fs/promises` builds its ESM facade,
// snapshotting the *original* functions before dephawk patches `fs.promises` —
// which used to let an ESM dependency read a secret with
// `import { readFile } from 'node:fs/promises'`. See {@link loadBuiltin}.
const { mkdir, writeFile } = loadBuiltin('node:fs/promises') as {
  mkdir: (path: string, options: { recursive: boolean }) => Promise<unknown>;
  writeFile: (path: string, data: string, encoding?: string) => Promise<void>;
};
import { dirname, resolve } from 'node:path';
import type { DhEvent } from '../../domain/event.js';
import type { Reporter } from '../../application/ports.js';
import { renderHtmlReport } from './html-format.js';

/** The filesystem operations the reporter needs — injectable for testing. */
export interface HtmlWriter {
  mkdir(dir: string): Promise<void>;
  writeFile(path: string, data: string): Promise<void>;
}

export interface HtmlReporterOptions {
  /** Output path (relative to cwd by default). */
  readonly outputPath?: string;
  readonly writer?: HtmlWriter;
  /** Clock for the "generated at" stamp. */
  readonly now?: () => Date;
  /** Where to announce the written path; defaults to stderr. */
  readonly log?: (message: string) => void;
}

const defaultWriter: HtmlWriter = {
  async mkdir(dir) {
    await mkdir(dir, { recursive: true });
  },
  async writeFile(path, data) {
    await writeFile(path, data, 'utf8');
  },
};

/**
 * Writes the shareable, self-contained HTML report to `.dephawk/report.html`
 * (by default). This is the viral artifact — one file you can open or attach.
 */
export class HtmlReporter implements Reporter {
  private readonly outputPath: string;
  private readonly writer: HtmlWriter;
  private readonly now: () => Date;
  private readonly log: (message: string) => void;

  constructor(options: HtmlReporterOptions = {}) {
    this.outputPath = options.outputPath ?? '.dephawk/report.html';
    this.writer = options.writer ?? defaultWriter;
    this.now = options.now ?? (() => new Date());
    this.log = options.log ?? ((message) => process.stderr.write(`${message}\n`));
  }

  async report(events: readonly DhEvent[]): Promise<void> {
    const html = renderHtmlReport(events, { generatedAt: this.now().toISOString() });
    const path = resolve(this.outputPath);
    await this.writer.mkdir(dirname(path));
    await this.writer.writeFile(path, html);
    this.log(`dephawk: HTML report written to ${path}`);
  }
}
