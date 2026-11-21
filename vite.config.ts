import { readFileSync } from 'node:fs';
import { defineConfig, type Plugin } from 'vite-plus';

const demoEntry = '<script type="module" src="./main.ts"></script>';

function inlineDemo(): Plugin {
  return {
    name: 'doublesec-inline-demo',
    generateBundle: {
      order: 'post',
      handler(_options, bundle) {
        const entry = Object.values(bundle).find((file) => file.type === 'chunk' && file.isEntry);
        if (!entry || entry.type !== 'chunk' || Object.keys(bundle).length !== 1) {
          this.error('The standalone demo must produce exactly one JavaScript chunk.');
        }

        const template = readFileSync(new URL('./demo/index.html', import.meta.url), 'utf8');
        if (!template.includes(demoEntry)) this.error('The standalone demo entry tag is missing.');

        const script = entry.code.replace(/<\/script/gi, '<\\/script');
        delete bundle[entry.fileName];
        this.emitFile({
          type: 'asset',
          fileName: 'demo.html',
          source: template.replace(demoEntry, () => `<script>${script}</script>`),
        });
      },
    },
  };
}

function nobleLicenses() {
  return ['@noble/ciphers/aes.js', '@noble/hashes/sha2.js']
    .map((entry) => {
      const license = readFileSync(new URL('LICENSE', import.meta.resolve(entry)), 'utf8');
      return `/*!\n${license.trim()}\n*/`;
    })
    .join('\n');
}

export default defineConfig(({ command, mode }) => {
  const demo = mode === 'standalone-demo';
  return {
    pack: {
      entry: ['src/index.ts'],
      format: 'esm',
      platform: 'neutral',
      dts: true,
      fixedExtension: false,
    },
    build: {
      target: 'es2022',
      emptyOutDir: false,
      minify: true,
      lib: {
        entry: demo ? 'demo/main.ts' : 'src/index.ts',
        formats: ['iife'],
        name: 'DoubleSec',
        fileName: () => 'doublesec.js',
      },
      rolldownOptions: { output: { postBanner: nobleLicenses } },
    },
    plugins: command === 'build' && demo ? [inlineDemo()] : [],
    lint: {
      ignorePatterns: ['dist/**', 'coverage/**'],
      options: { typeAware: true, typeCheck: true },
    },
    test: {
      include: ['test/**/*.test.mjs'],
      environment: 'node',
      coverage: {
        include: ['src/**/*.ts'],
      },
    },
    fmt: {
      ignorePatterns: ['dist/**', 'coverage/**'],
      singleQuote: true,
      printWidth: 100,
    },
  };
});
