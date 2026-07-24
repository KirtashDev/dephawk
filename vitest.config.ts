import { defineConfig } from 'vitest/config';

// Coverage thresholds encode the Definition of Done: the pure layers
// (domain + application) must stay at or above 90 %. Adapters are covered by at
// least one behaviour fixture each but are not held to the same numeric bar,
// because they poke real Node built-ins where branches are runtime-dependent.
export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/index.ts',
        'src/register.ts',
        'src/cli.ts',
        'src/**/index.ts',
      ],
      thresholds: {
        'src/domain/**': {
          statements: 90,
          branches: 90,
          functions: 90,
          lines: 90,
        },
        'src/application/**': {
          statements: 90,
          branches: 90,
          functions: 90,
          lines: 90,
        },
      },
    },
  },
});
