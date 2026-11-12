import { defineConfig } from "vitest/config";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  plugins: [tailwindcss()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/health": "http://127.0.0.1:8080",
    },
  },
  test: {
    maxWorkers: 1,
    fileParallelism: false,
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
