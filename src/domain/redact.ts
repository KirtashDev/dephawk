/**
 * Strip secret-looking values out of the strings dephawk writes down.
 *
 * dephawk records *what* a dependency touched, and for a spawn that means the
 * whole command line: `curl -H "Authorization: Bearer ghp_…"` used to land
 * verbatim in the console report, `.dephawk/report.html`, the SARIF and the
 * JSONL sink. The GitHub Action then publishes those — into the job summary,
 * which is public for a public repository, and into code scanning. A tool whose
 * job is to stop secrets leaving must not be the thing that leaks one.
 *
 * Applied to an event's `detail` and `reason` only, never to the stack frames
 * (file paths and line numbers) and never before policy evaluation — rules are
 * matched against what actually happened, and only the record is redacted.
 *
 * This is a name-and-shape heuristic, like the rest of this module's
 * neighbours: it catches the common forms and cannot promise more. Paths,
 * hostnames and argument *names* stay legible on purpose — a redacted line you
 * cannot act on is its own kind of useless.
 */

import { isSensitiveEnv } from './sensitivity.js';

const PLACEHOLDER = '***';

/**
 * `name=value` where the name itself looks secret. One pattern covers command
 * flags (`--token=…`), inline environment (`NPM_TOKEN=…`) and URL query
 * parameters (`?access_token=…`), because the check is on the name and
 * {@link isSensitiveEnv} already knows which names those are. The value ends at
 * whitespace, a quote or `&`, so only the offending query parameter is lost.
 */
const NAMED_ASSIGNMENT = /([A-Za-z0-9_.-]+)=([^\s'"&]+)/g;

/**
 * The same, space-separated: `--token abc`, `-p hunter2`. A value starting with
 * `-` is the next flag, not a value, so it is left alone.
 */
const NAMED_FLAG = /(^|\s)(--?[A-Za-z0-9_.-]+)(\s+)([^\s'"-][^\s'"]*)/g;

/** Ordered, unconditional replacements: authorization headers, URL userinfo. */
const CREDENTIAL_PATTERNS: readonly [RegExp, string][] = [
  // Authorization: Bearer <token> / Basic <base64>
  [/\b(bearer|basic)(\s+)([A-Za-z0-9._~+/=-]{8,})/gi, `$1$2${PLACEHOLDER}`],
  // scheme://user:password@host
  [/(\/\/[^\s:/@]+:)([^\s@/]+)(@)/g, `$1${PLACEHOLDER}$3`],
];

/**
 * Token shapes that identify themselves. The prefix survives — knowing a GitHub
 * token was on the command line is the useful part; the token is not.
 */
const TOKEN_SHAPES: readonly [RegExp, string][] = [
  [/\b(gh[pousr]_)[A-Za-z0-9]{16,}\b/g, `$1${PLACEHOLDER}`],
  [/\b(github_pat_)[A-Za-z0-9_]{20,}\b/g, `$1${PLACEHOLDER}`],
  [/\b(npm_)[A-Za-z0-9]{16,}\b/g, `$1${PLACEHOLDER}`],
  [/\b(glpat-)[A-Za-z0-9_-]{16,}\b/g, `$1${PLACEHOLDER}`],
  [/\b(xox[baprs]-)[A-Za-z0-9-]{10,}\b/g, `$1${PLACEHOLDER}`],
  [/\b(sk-)[A-Za-z0-9_-]{16,}\b/g, `$1${PLACEHOLDER}`],
  [/\b(A[KS]IA)[0-9A-Z]{16}\b/g, `$1${PLACEHOLDER}`],
  // A JWT: three base64url segments. Its payload is readable by anyone.
  [
    /\b(eyJ)[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    `$1${PLACEHOLDER}`,
  ],
];

/** Replace secret-looking values in `text`, keeping the names around them. */
export function redactSecrets(text: string): string {
  let redacted = text.replace(NAMED_ASSIGNMENT, (match, name: string) =>
    isSensitiveEnv(name) ? `${name}=${PLACEHOLDER}` : match,
  );

  redacted = redacted.replace(
    NAMED_FLAG,
    (match, before: string, flag: string, gap: string) =>
      isSensitiveEnv(flag) ? `${before}${flag}${gap}${PLACEHOLDER}` : match,
  );

  for (const [pattern, replacement] of [...CREDENTIAL_PATTERNS, ...TOKEN_SHAPES]) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

/** C0 control characters (NUL-US incl. TAB/LF/CR/ESC) and DEL. */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;

/**
 * Replace every control character (including ESC, CR and LF) with a space.
 *
 * A `detail` is attacker-chosen text — a path, host, or command line a dependency
 * picked — and it is interpolated into the terminal report, the drafted config's
 * comments and quoted strings, and the JSONL sink. Left raw it could inject ANSI
 * escapes to spoof or erase findings on the TTY, or a newline to smuggle a second
 * `default:` bucket (an allow-all self-grant) or a `SyntaxError` into a generated
 * config. Stripping runs *before* {@link redactSecrets}, so a control character
 * cannot split a token to slip past redaction either.
 */
export function stripControlChars(text: string): string {
  return text.replace(CONTROL_CHARS, ' ');
}
