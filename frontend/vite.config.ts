import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API + Keycloak in dev so the browser only ever talks to one origin
      // (tightens CSP connect-src and avoids CORS surface).
      "/api": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split heavy visualization libs so the initial bundle stays lean and
        // the graph/charts load only on the routes that use them.
        manualChunks: {
          "react-vendor": ["react", "react-dom", "react-router-dom"],
          charts: ["recharts"],
          graph: ["@xyflow/react"],
          data: ["@tanstack/react-query", "axios", "zustand"],
        },
      },
    },
  },
});
