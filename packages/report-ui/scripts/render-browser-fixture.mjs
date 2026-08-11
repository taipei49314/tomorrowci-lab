import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(packageRoot, "../..");
const fixtureRoot = path.join(packageRoot, ".tmp", "browser-fixture");
const reportPath = path.join(fixtureRoot, "report.html");

await rm(fixtureRoot, { recursive: true, force: true });
await mkdir(fixtureRoot, { recursive: true });

const command = spawnSync(
  "cargo",
  ["run", "--quiet", "-p", "tomorrowci-report", "--example", "browser_fixture", "--", reportPath],
  { cwd: repoRoot, encoding: "utf8", stdio: "inherit" },
);
if (command.status !== 0) {
  process.exit(command.status ?? 1);
}

console.log(reportPath);
