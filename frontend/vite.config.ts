import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  // Where the dev server proxies /api. Override in .env.local with VITE_API_PROXY
  // if your backend runs on a non-default port (e.g. another project holds 8000).
  const apiProxy = env.VITE_API_PROXY || "http://localhost:8000";

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: { "@": path.resolve(__dirname, "./src") },
    },
    server: {
      port: 5173,
      proxy: {
        "/api": { target: apiProxy, changeOrigin: true },
      },
    },
    build: {
      outDir: "dist",
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks: {
            "react-vendor": ["react", "react-dom", "react-router-dom"],
            charts: ["recharts"],
            graph: ["@xyflow/react"],
            data: ["@tanstack/react-query", "axios", "zustand"],
          },
        },
      },
    },
  };
});
