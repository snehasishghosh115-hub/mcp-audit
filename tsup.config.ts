import { defineConfig } from 'tsup';

export default defineConfig([
  // CLI entry — needs the shebang
  {
    entry: ['src/cli.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: false,
    platform: 'node',
    target: 'node18',
    outDir: 'dist',
    banner: { js: '#!/usr/bin/env node' },
  },
  // Library entry — no shebang; consumers import this
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    platform: 'node',
    target: 'node18',
    outDir: 'dist',
  },
]);