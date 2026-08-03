import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { DhEvent } from '../../domain/event.js';
import type { Reporter } from '../../application/ports.js';
import { renderSarifReport } from './sarif-format.js';

/** The filesystem operations the reporter needs — injectable for testing. */
export interface SarifWriter {
  mkdir(dir: string): Promise<void>;
  writeFile(path: string, data: string): Promise<void>;
}

export interface SarifReporterOptions {
  /** Output path (relative to cwd by default). */
  readonly outputPath?: string;
  readonly writer?: SarifWriter;
  /** Directory result paths are made relative to; defaults to cwd. */
  readonly rootPath?: string;
  /** dephawk's version, recorded in the tool driver. */
  readonly toolVersion?: string;
  /** Where to announce the written path; defaults to stderr. */
  readonly log?: (message: string) => void;
}

const defaultWriter: SarifWriter = {
  async mkdir(dir) {
    await mkdir(dir, { recursive: true });
  },
  async writeFile(path, data) {
    await writeFile(path, data, 'utf8');
  },
};

/**
 * Writes findings as a SARIF file for GitHub code scanning to ingest.
 *
 * This is what turns a report you have to go and read into an annotation on the
 * pull request that introduced the dependency. Pair it with `--fail-on` and
 * dephawk can gate a merge instead of describing what happened afterwards.
 */
export class SarifReporter implements Reporter {
  private readonly outputPath: string;
  private readonly writer: SarifWriter;
  private readonly rootPath: string;
  private readonly toolVersion: string;
  private readonly log: (message: string) => void;

  constructor(options: SarifReporterOptions = {}) {
    this.outputPath = options.outputPath ?? '.dephawk/report.sarif';
    this.writer = options.writer ?? defaultWriter;
    this.rootPath = options.rootPath ?? process.cwd();
    this.toolVersion = options.toolVersion ?? '0.0.0';
    this.log = options.log ?? ((message) => process.stderr.write(`${message}\n`));
  }

  async report(events: readonly DhEvent[]): Promise<void> {
    const sarif = renderSarifReport(events, {
      toolVersion: this.toolVersion,
      rootPath: this.rootPath,
    });
    const path = resolve(this.outputPath);
    await this.writer.mkdir(dirname(path));
    await this.writer.writeFile(path, sarif);
    this.log(`dephawk: SARIF report written to ${path}`);
  }
}
