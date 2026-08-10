import type { CapabilityRequest } from './capability-request.js';
import type { Policy, PackagePolicy } from './policy.js';
import type { Verdict } from './verdict.js';
import { isPersistenceTarget, isSensitiveEnv, isSensitivePath } from './sensitivity.js';
import { protectedPathAffectedBy } from './protected-path.js';
import { isCrossPackageWrite, packageOwningPath } from './package-dir.js';
import { extractHost, hostMatchesAny } from './host.js';
import { pathMatchesAny } from './path-glob.js';

/**
 * The core evaluation contract. Given a request, decide whether policy permits
 * it and whether it is sensitive. Pure: same input → same output, no I/O.
 */
export interface PolicyEngine {
  evaluate(req: CapabilityRequest): Verdict;
}

/**
 * The default {@link PolicyEngine}: mundane actions pass, sensitive ones must be
 * allowlisted per package. Network is allowlist-only regardless of sensitivity
 * (a dependency phoning home is the whole point).
 *
 * Trust follows {@link import('./origin.js').Origin}, not the package name:
 *
 * - `application` — the user's own code, always allowed. dephawk watches
 *   dependencies, not you.
 * - `dependency`  — evaluated against that package's rules, falling back to the
 *   default bucket.
 * - `unknown`     — attribution found no owner at all. Evaluated against the
 *   *default* bucket rather than trusted, so a dependency cannot buy itself a
 *   free pass by laundering a call until its frames fall off the stack.
 *
 * Ahead of all of that sits one rule that answers to nobody: filesystem access
 * to dephawk's own {@link import('./protected-path.js') protected paths} is
 * refused for every origin and in every mode.
 */
export class RulePolicyEngine implements PolicyEngine {
  private readonly policy: Policy;
  private readonly protectedPaths: readonly string[];

  constructor(policy: Policy, protectedPaths: readonly string[] = []) {
    this.policy = policy;
    this.protectedPaths = protectedPaths;
  }

  evaluate(req: CapabilityRequest): Verdict {
    const sensitive = detectSensitive(req);

    const tampering = this.detectTampering(req);
    if (tampering !== null) {
      return tampering;
    }

    if (req.origin === 'application') {
      return { allowed: true, sensitive };
    }

    const pkg =
      req.package === null
        ? this.policy.default
        : (this.policy.packages[req.package] ?? this.policy.default);
    return evaluateCapability(req, pkg, sensitive);
  }

  /**
   * A verdict when the request targets one of dephawk's own files, or null.
   *
   * Reads are left alone — knowing the sink exists tells an attacker nothing it
   * cannot learn from `DEPHAWK_SINK` anyway — but any write is refused
   * outright, in observe mode as much as in enforce. This is not policy about
   * the program; it is dephawk keeping its audit log intact.
   */
  private detectTampering(req: CapabilityRequest): Verdict | null {
    if (req.capability !== 'fs.write' || this.protectedPaths.length === 0) {
      return null;
    }
    const target = protectedPathAffectedBy(req.detail, this.protectedPaths);
    if (target === null) {
      return null;
    }
    return {
      allowed: false,
      sensitive: true,
      mandatory: true,
      reason: `${target} is dephawk's own audit log and cannot be modified`,
    };
  }
}

function detectSensitive(req: CapabilityRequest): boolean {
  switch (req.capability) {
    case 'fs.write':
      // Writing into another package's directory installs code that will run
      // as that package — high signal wherever the file sits. Writing a shell
      // startup file is persistence for the same reason.
      return (
        isSensitivePath(req.detail) ||
        isPersistenceTarget(req.detail) ||
        isCrossPackageWrite(req.package, packageOwningPath(req.detail))
      );
    case 'fs.read':
      return isSensitivePath(req.detail);
    case 'env.read':
      return isSensitiveEnv(req.detail);
    case 'process.spawn':
      // Spawning a process is always high signal — that's the curl-pipe-sh move.
      return true;
    case 'process.native':
      // Loading a native addon bypasses all JS-level interception — high signal.
      return true;
    case 'code.eval':
      // Dynamically executing compiled code is the obfuscated-payload move.
      return true;
    case 'process.memory':
      // Dumping the heap or the diagnostic report exposes every secret in
      // memory and every env var at once — high signal.
      return true;
    case 'net.listen':
      // Opening an inbound listener is a backdoor primitive — high signal.
      return true;
    case 'net.connect':
    case 'net.resolve':
    case 'os.info':
      return false;
  }
}

function allow(sensitive: boolean): Verdict {
  return { allowed: true, sensitive };
}

function deny(sensitive: boolean, reason: string): Verdict {
  return { allowed: false, sensitive, reason };
}

function evaluateCapability(
  req: CapabilityRequest,
  pkg: PackagePolicy,
  sensitive: boolean,
): Verdict {
  switch (req.capability) {
    case 'net.connect': {
      const host = extractHost(req.detail);
      const allowlist = pkg.net?.connect ?? [];
      return hostMatchesAny(host, allowlist)
        ? allow(sensitive)
        : deny(sensitive, `network connection to ${host} is not in the allowlist`);
    }

    case 'net.resolve': {
      // DNS reuses the connect allowlist: resolving a host is a connection
      // precursor (and a DNS-exfil channel), so it is gated by the same rule.
      const host = extractHost(req.detail);
      const allowlist = pkg.net?.connect ?? [];
      return hostMatchesAny(host, allowlist)
        ? allow(sensitive)
        : deny(sensitive, `DNS resolution of ${host} is not in the allowlist`);
    }

    case 'net.listen': {
      return pkg.net?.listen === true
        ? allow(sensitive)
        : deny(sensitive, `opening an inbound listener on ${req.detail} is not allowed`);
    }

    case 'process.spawn': {
      return pkg.spawn === true
        ? allow(sensitive)
        : deny(sensitive, 'spawning child processes is not allowed');
    }

    case 'process.native': {
      return pkg.native === true
        ? allow(sensitive)
        : deny(sensitive, `loading native addon ${req.detail} is not allowed`);
    }

    case 'code.eval': {
      return pkg.eval === true
        ? allow(sensitive)
        : deny(sensitive, 'dynamic code execution (vm) is not allowed');
    }

    case 'process.memory': {
      return pkg.memory === true
        ? allow(sensitive)
        : deny(sensitive, `dumping process memory (${req.detail}) is not allowed`);
    }

    case 'env.read': {
      if (!sensitive) {
        return allow(sensitive);
      }
      const env = pkg.env ?? false;
      const permitted = env === true || (Array.isArray(env) && env.includes(req.detail));
      return permitted
        ? allow(sensitive)
        : deny(sensitive, `reading secret env var ${req.detail} is not allowed`);
    }

    case 'fs.read': {
      if (!sensitive) {
        return allow(sensitive);
      }
      return pathMatchesAny(req.detail, pkg.fs?.read ?? [])
        ? allow(sensitive)
        : deny(sensitive, `reading sensitive path ${req.detail} is not allowed`);
    }

    case 'fs.write': {
      // One package writing into another's directory is refused on its own
      // terms, not via the path allowlist: the file being written is ordinary,
      // and what makes it an attack is *who* is writing it. Granting a write
      // allowlist for your own paths must never buy the right to overwrite a
      // sibling dependency.
      const owner = packageOwningPath(req.detail);
      if (isCrossPackageWrite(req.package, owner)) {
        return deny(
          true,
          `writing into another package's directory (${String(owner)}) would ` +
            `make code run as that package`,
        );
      }
      if (!sensitive) {
        return allow(sensitive);
      }
      return pathMatchesAny(req.detail, pkg.fs?.write ?? [])
        ? allow(sensitive)
        : deny(sensitive, `writing sensitive path ${req.detail} is not allowed`);
    }

    case 'os.info': {
      // Informational; recorded but never blocked.
      return allow(sensitive);
    }
  }
}
