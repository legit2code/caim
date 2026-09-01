import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, Plugin } from 'vite';

function isolateWorkersPlugin(): Plugin {
  return {
    name: 'isolate-workers-boundary',
    resolveId(source) {
      if (source.includes('workers/') || source.startsWith('@workers')) {
        throw new Error(
          `[Architecture Invariant Violation] Client bundle must not import worker packages directly (${source}). Workers run out-of-process.`
        );
      }
      return null;
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [isolateWorkersPlugin(), react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      hmr: process.env.DISABLE_HMR === 'true' ? false : undefined,
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
