import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const nodeTests = spawnSync(
  process.execPath,
  ["--test", path.join(packageRoot, "test", "escape.test.js")],
  { cwd: packageRoot, encoding: "utf8", stdio: "inherit" },
);
if (nodeTests.status !== 0) process.exit(nodeTests.status ?? 1);

const vitest = spawnSync(
  process.execPath,
  [path.join(packageRoot, "node_modules", "vitest", "vitest.mjs"), "run", "--config", path.join(packageRoot, "vitest.config.ts")],
  { cwd: packageRoot, encoding: "utf8", stdio: "inherit" },
);
process.exit(vitest.status ?? 1);
