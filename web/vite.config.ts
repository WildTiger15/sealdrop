import { defineConfig } from "vite";

// The Go server serves dist/ and the API on one origin (needed for passkeys).
export default defineConfig({
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: { input: { main: "index.html", audit: "audit.html" } },
  },
  server: { proxy: { "/api": "http://localhost:8080" } },
});
