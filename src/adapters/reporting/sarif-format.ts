import { CAPABILITY_META, type Capability } from '../../domain/capability.js';
import type { DhEvent } from '../../domain/event.js';
import { displayPackage, summarize, type Row } from './report-model.js';

const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const TOOL_URI = 'https://github.com/KirtashDev/dephawk';

/**
 * Where results are anchored when the offending frame is not a file in the
 * repository — which is the common case, since dependencies live in
 * `node_modules` and that is usually not checked in. GitHub needs a location to
 * attach an alert to; the manifest that pulled the dependency in is the most
 * honest one available.
 */
const FALLBACK_ARTIFACT = 'package.json';

export interface SarifMeta {
  /** dephawk's own version, recorded in the tool driver. */
  readonly toolVersion: string;
  /** Absolute directory that result paths are made relative to. */
  readonly rootPath: string;
}

/**
 * Render the findings as SARIF 2.1.0.
 *
 * SARIF is what makes dephawk a participant in code review rather than a thing
 * you read logs from: GitHub ingests it and turns each finding into an
 * annotation on the pull request that introduced it. Pure function of its
 * inputs, so the shape is testable without touching a filesystem or a network.
 *
 * Only flagged rows are emitted. A SARIF file is a list of findings; shipping
 * every mundane call as an "informational result" would bury the two that
 * matter under thousands that do not.
 */
export function renderSarifReport(events: readonly DhEvent[], meta: SarifMeta): string {
  const { flagged } = summarize(events);
  const capabilities = [...new Set(flagged.map((row) => row.capability))].sort();

  const report = {
    $schema: SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'dephawk',
            informationUri: TOOL_URI,
            version: meta.toolVersion,
            rules: capabilities.map(describeRule),
          },
        },
        results: flagged.map((row) => describeResult(row, meta.rootPath)),
      },
    ],
  };

  return `${JSON.stringify(report, null, 2)}\n`;
}

function describeRule(capability: Capability): unknown {
  const meta = CAPABILITY_META[capability];
  return {
    id: capability,
    name: capability.replace(/[.-](\w)/g, (_, letter: string) => letter.toUpperCase()),
    shortDescription: { text: meta.description },
    fullDescription: {
      text: `${meta.description} dephawk attributes the call to the package that made it and checks it against your policy.`,
    },
    helpUri: `${TOOL_URI}#what-it-watches`,
    properties: { tags: ['security', 'supply-chain', capability] },
  };
}

function describeResult(row: Row, rootPath: string): unknown {
  return {
    ruleId: row.capability,
    level: row.severity === 'critical' ? 'error' : 'warning',
    message: { text: describeFinding(row) },
    locations: [
      {
        physicalLocation: locationOf(row.stack, rootPath),
      },
    ],
    // Lets GitHub track one finding across runs instead of reopening it each
    // time. Deliberately excludes the count, which changes run to run.
    partialFingerprints: {
      'dephawkFinding/v1': [row.package ?? row.origin, row.capability, row.detail].join(
        '|',
      ),
    },
  };
}

function describeFinding(row: Row): string {
  const who = displayPackage(row);
  const what = CAPABILITY_META[row.capability].description.replace(/\.$/, '');
  const parts = [`${who}: ${what} — ${row.detail}`];

  if (row.reason !== undefined) {
    parts.push(row.reason);
  } else if (!row.allowed) {
    parts.push('not permitted by policy');
  } else {
    parts.push('permitted by policy, but sensitive');
  }

  if (row.blocked) {
    parts.push('blocked');
  } else if (!row.allowed) {
    parts.push('would be blocked in enforce mode');
  }

  if (row.count > 1) {
    parts.push(`seen ${row.count} times`);
  }

  return `${parts.join('. ')}.`;
}

/** A frame location: `at fn (/path/file.js:12:3)` or `at /path/file.js:12:3`. */
const FRAME = /\(?([^()\s]+):(\d+):(\d+)\)?$/;

/**
 * Point at the file that made the call, when it is inside the project.
 *
 * Frames from outside the root — Node internals, a globally installed tool —
 * cannot be turned into a repository-relative URI, and an absolute path in
 * SARIF is not something GitHub can map to a blob. Those fall back to the
 * manifest rather than being dropped: a finding with no location is a finding
 * nobody sees.
 */
function locationOf(stack: readonly string[], rootPath: string): unknown {
  const root = rootPath.endsWith('/') ? rootPath : `${rootPath}/`;

  for (const frame of stack) {
    const match = FRAME.exec(frame.trim());
    if (match === null) {
      continue;
    }
    const [, rawPath, line, column] = match as unknown as [
      string,
      string,
      string,
      string,
    ];
    const path = rawPath.replace(/^file:\/\//, '');
    if (!path.startsWith(root)) {
      continue;
    }
    return {
      artifactLocation: { uri: path.slice(root.length) },
      region: { startLine: Number(line), startColumn: Number(column) },
    };
  }

  return {
    artifactLocation: { uri: FALLBACK_ARTIFACT },
    region: { startLine: 1 },
  };
}
