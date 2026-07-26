import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tsConfigPaths from "vite-tsconfig-paths";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";

const apiProxyTarget = process.env.DASHBOARD_API_PROXY_TARGET || "http://localhost:8080";

export default defineConfig({
  envDir: "../../",
  build: { target: "esnext" },
  server: {
    port: 5173,
    host: true,
    allowedHosts: ["codewire.sh", ".ts.net", "web", "localhost", ".localhost"],
    proxy: {
      "/api": {
        target: apiProxyTarget,
        changeOrigin: true,
      },
      "/codewire.v1": {
        target: apiProxyTarget,
        changeOrigin: true,
      },
      "/codewire.console.v1": {
        target: apiProxyTarget,
        changeOrigin: true,
      },
      "/codewire.admin.v1": {
        target: apiProxyTarget,
        changeOrigin: true,
      },
      "/docs": {
        target: "http://docs:4321",
        changeOrigin: true,
      },
    },
  },
  plugins: [
    TanStackRouterVite(),
    tsConfigPaths(),
    react(),
  ],
});
