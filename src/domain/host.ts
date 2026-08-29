/**
 * Pure host parsing and prefix-glob matching used by network policy.
 *
 * A pattern is either an exact host (`api.example.com`) or a prefix glob
 * (`*.example.com`). The glob matches the apex and any subdomain:
 * `*.example.com` matches `example.com`, `a.example.com`, `a.b.example.com`.
 * No other glob syntax is supported — this is deliberately small and auditable.
 */

/**
 * Extract a bare hostname from an outbound-connection detail string.
 * Accepts full URLs (`https://host:443/path`), `host:port`, and bare hosts.
 * Returns the lowercased hostname, or the trimmed input if nothing parses.
 */
export function extractHost(detail: string): string {
  let rest = detail.trim();

  const schemeIndex = rest.indexOf('://');
  if (schemeIndex !== -1) {
    rest = rest.slice(schemeIndex + 3);
  }

  // Strip userinfo (`user:pass@host`).
  const atIndex = rest.indexOf('@');
  if (atIndex !== -1) {
    rest = rest.slice(atIndex + 1);
  }

  // Cut at the first path/query/fragment boundary.
  const boundary = rest.search(/[/?#]/);
  if (boundary !== -1) {
    rest = rest.slice(0, boundary);
  }

  // IPv6 literal in brackets: keep the inside, ignore any :port after `]`.
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close !== -1) {
      return rest.slice(1, close).toLowerCase();
    }
  }

  // Strip a trailing :port (but not for the bracketless IPv6 case handled above).
  const colonIndex = rest.lastIndexOf(':');
  if (colonIndex !== -1 && !rest.includes(']')) {
    const maybePort = rest.slice(colonIndex + 1);
    if (/^\d+$/.test(maybePort)) {
      rest = rest.slice(0, colonIndex);
    }
  }

  return rest.toLowerCase();
}

/**
 * The explicit port in an outbound-connection detail, or null.
 *
 * Explicit only: a scheme's default port is not inferred, because the one caller
 * asks "is this a well-known *infrastructure* port", and `https://host` with no
 * port is never one. Parsing mirrors {@link extractHost} step for step so the two
 * agree on where the host ends and the port begins.
 */
export function extractPort(detail: string): number | null {
  let rest = detail.trim();

  const schemeIndex = rest.indexOf('://');
  if (schemeIndex !== -1) {
    rest = rest.slice(schemeIndex + 3);
  }
  const atIndex = rest.indexOf('@');
  if (atIndex !== -1) {
    rest = rest.slice(atIndex + 1);
  }
  const boundary = rest.search(/[/?#]/);
  if (boundary !== -1) {
    rest = rest.slice(0, boundary);
  }

  // A bracketed IPv6 literal: the port, if any, follows the `]`.
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close === -1) {
      return null;
    }
    rest = rest.slice(close + 1);
    return rest.startsWith(':') ? toPort(rest.slice(1)) : null;
  }

  const colonIndex = rest.lastIndexOf(':');
  // Bare IPv6 (more than one colon) has no port to read without brackets.
  if (colonIndex === -1 || rest.indexOf(':') !== colonIndex) {
    return null;
  }
  return toPort(rest.slice(colonIndex + 1));
}

function toPort(text: string): number | null {
  if (!/^\d{1,5}$/.test(text)) {
    return null;
  }
  const port = Number(text);
  return port >= 1 && port <= 65535 ? port : null;
}

/** True when `host` matches a single allowlist `pattern`. */
export function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();

  if (p.startsWith('*.')) {
    const suffix = p.slice(2); // e.g. "example.com"
    return h === suffix || h.endsWith(`.${suffix}`);
  }
  return h === p;
}

/** True when `host` matches any pattern in `patterns`. */
export function hostMatchesAny(host: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => hostMatches(host, pattern));
}
