import { defineConfig } from "vite";
// Builds the side panel page + background service worker into dist/ (load dist/ as an unpacked extension).
export default defineConfig({
  build: {
    outDir: "dist",
    rollupOptions: {
      input: { sidepanel: "sidepanel.html", background: "src/background.ts" },
      output: { entryFileNames: "[name].js", chunkFileNames: "chunks/[name]-[hash].js", assetFileNames: "assets/[name]-[hash][extname]" },
    },
  },
  test: { include: ["tests/**/*.test.ts"] },
} as any);
