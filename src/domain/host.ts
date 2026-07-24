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
