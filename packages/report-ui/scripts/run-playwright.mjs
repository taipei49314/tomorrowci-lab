import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const playwright = spawnSync(
  process.execPath,
  [path.join(packageRoot, "node_modules", "@playwright", "test", "cli.js"), "test", "--config", path.join(packageRoot, "playwright.config.ts")],
  { cwd: packageRoot, encoding: "utf8", stdio: "inherit" },
);
process.exit(playwright.status ?? 1);
