import { defineConfig } from "vitest/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root,
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.{ts,tsx}"],
    exclude: ["test/**/*.e2e.ts"],
    globals: true,
    restoreMocks: true,
  },
});
