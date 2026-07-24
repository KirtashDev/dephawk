import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    register: 'src/register.ts',
    cli: 'src/cli.ts',
  },
  format: ['esm'],
  target: 'node20',
  platform: 'node',
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  shims: false,
  // dephawk ships zero runtime dependencies; nothing to externalize.
  external: [],
});
