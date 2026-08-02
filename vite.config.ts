import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // Pre-bundle heavy deps at startup so the WebView's first page load doesn't
  // wait for Vite to transform the whole module graph (react + supabase-js
  // unminified ESM = ~30s in dev). With these pre-optimized, first render is ~1-2s.
  optimizeDeps: {
    include: [
      "react",
      "react-dom",
      "react-dom/client",
      "@supabase/supabase-js",
      "@tauri-apps/api/core",
      "@tauri-apps/api/event",
    ],
  },
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    // Bind IPv4 explicitly: Vite's default `localhost` can resolve to ::1 (IPv6)
    // only, which WebView2's initial navigation silently fails on -> blank window.
    host: host || "127.0.0.1",
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
