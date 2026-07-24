// Sample dephawk policy for the demo.
//
// The default bucket allows nothing sensitive, so "sneaky-dependency" — which
// is not listed under `packages` — has all of its shady calls flagged (observe)
// or blocked (enforce). A legitimately-networked package would be allowlisted
// here, e.g.  "@sentry/node": { net: { connect: ["*.sentry.io"] } }.
export default {
  mode: 'observe', // override at runtime with DEPHAWK_MODE=enforce
  default: {
    net: { connect: [] },
    spawn: false,
    env: false,
  },
  packages: {},
};
