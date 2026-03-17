import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, existsSync, readFileSync, writeFileSync, rmSync } from 'fs';

// Post-build plugin: copy manifest + icons, fix HTML location
const copyStaticPlugin = {
  name: 'copy-static',
  closeBundle() {
    const distDir = resolve(__dirname, 'dist');

    // Copy manifest.json
    copyFileSync(
      resolve(__dirname, 'manifest.json'),
      resolve(distDir, 'manifest.json'),
    );

    // Copy icons
    const iconsDir = resolve(distDir, 'icons');
    if (!existsSync(iconsDir)) mkdirSync(iconsDir, { recursive: true });
    for (const size of [16, 48, 128]) {
      const src = resolve(__dirname, `icons/icon${size}.png`);
      if (existsSync(src)) {
        copyFileSync(src, resolve(iconsDir, `icon${size}.png`));
      }
    }

    // Move popup HTML from dist/src/popup/index.html → dist/popup/index.html
    // (Vite preserves dir structure relative to project root for HTML inputs)
    const htmlSrc = resolve(distDir, 'src/popup/index.html');
    const htmlDst = resolve(distDir, 'popup/index.html');
    if (existsSync(htmlSrc)) {
      let html = readFileSync(htmlSrc, 'utf-8');
      // Fix script src: ensure it's just "popup.js" (no leading path)
      html = html.replace(/src="[^"]*popup\.js"/g, 'src="popup.js"');
      // Fix modulepreload absolute paths → relative (prepend ../ since popup/ is one level in)
      html = html.replace(/href="\/chunks\//g, 'href="../chunks/');
      writeFileSync(htmlDst, html);
      // Remove leftover src/ directory
      rmSync(resolve(distDir, 'src'), { recursive: true, force: true });
    }
  },
};

export default defineConfig({
  plugins: [react(), copyStaticPlugin],
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'production'),
  },
  build: {
    target: 'es2020',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/index.html'),
        background: resolve(__dirname, 'src/background/index.ts'),
        content: resolve(__dirname, 'src/content/inject.ts'),
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === 'popup') return 'popup/popup.js';
          return '[name].js';
        },
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: '[name].[ext]',
        manualChunks: undefined,
      },
    },
    outDir: 'dist',
    emptyOutDir: true,
    minify: false,
    sourcemap: false,
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
});
