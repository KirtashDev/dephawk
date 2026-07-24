import { createEvent, type DhEvent } from '../../../src/domain/event.js';
import type { CreateEventInput } from '../../../src/domain/event.js';

/** Build a DhEvent with sensible defaults for reporting tests. */
export function ev(partial: Partial<CreateEventInput> = {}): DhEvent {
  return createEvent({
    capability: 'fs.read',
    package: 'p',
    detail: 'd',
    stack: [],
    sensitive: false,
    allowed: true,
    blocked: false,
    timestamp: 0,
    ...partial,
  });
}

/** A representative mix: one violation, one sensitive-but-allowed, two normal. */
export const mixed: DhEvent[] = [
  ev({
    capability: 'net.connect',
    package: 'evil-pkg',
    detail: 'https://collector.sketchy.example',
    sensitive: false,
    allowed: false,
    reason: 'not allowlisted',
  }),
  ev({
    capability: 'env.read',
    package: '@sentry/node',
    detail: 'SENTRY_DSN',
    sensitive: true,
    allowed: true,
  }),
  ev({ capability: 'fs.read', package: 'lodash', detail: '/app/x.js' }),
  ev({ capability: 'fs.read', package: 'lodash', detail: '/app/y.js' }),
];
