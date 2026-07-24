import type { CapabilityRequest } from './capability-request.js';
import type { Policy, PackagePolicy } from './policy.js';
import type { Verdict } from './verdict.js';
import { isSensitiveEnv, isSensitivePath } from './sensitivity.js';
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
 * (a dependency phoning home is the whole point). The user's own code
 * (`package === null`) is always allowed — dephawk watches dependencies, not you.
 */
export class RulePolicyEngine implements PolicyEngine {
  private readonly policy: Policy;

  constructor(policy: Policy) {
    this.policy = policy;
  }

  evaluate(req: CapabilityRequest): Verdict {
    const sensitive = detectSensitive(req);

    if (req.package === null) {
      return { allowed: true, sensitive };
    }

    const pkg = this.policy.packages[req.package] ?? this.policy.default;
    return evaluateCapability(req, pkg, sensitive);
  }
}

function detectSensitive(req: CapabilityRequest): boolean {
  switch (req.capability) {
    case 'fs.read':
    case 'fs.write':
      return isSensitivePath(req.detail);
    case 'env.read':
      return isSensitiveEnv(req.detail);
    case 'process.spawn':
      // Spawning a process is always high signal — that's the curl-pipe-sh move.
      return true;
    case 'net.connect':
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

    case 'process.spawn': {
      return pkg.spawn === true
        ? allow(sensitive)
        : deny(sensitive, 'spawning child processes is not allowed');
    }

    case 'env.read': {
      if (!sensitive) {
        return allow(sensitive);
      }
      const env = pkg.env ?? false;
      const permitted =
        env === true || (Array.isArray(env) && env.includes(req.detail));
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
