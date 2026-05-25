import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // During local dev, /api/llm is served by server/proxy.mjs
      // In production (Netlify), it's served by netlify/functions/llm.js
      "/api": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
    },
  },
});
