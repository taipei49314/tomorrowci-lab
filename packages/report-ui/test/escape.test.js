import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { escapeHtml, sanitizeLog } from "../src/escape.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("XSS hardening", () => {
  it("escapes script tags", () => {
    const s = escapeHtml('<script>alert(1)</script>');
    assert.equal(s.includes("<script>"), false);
    assert.equal(s.includes("&lt;script&gt;"), true);
  });

  it("sanitizes ansi + html", () => {
    const s = sanitizeLog("\u001b[31m<img onerror=alert(1)>\u001b[0m");
    assert.equal(s.includes("\u001b"), false);
    assert.equal(s.includes("<img"), false);
    assert.equal(s.includes("&lt;img"), true);
  });
});

describe("keyboard / a11y contract markers", () => {
  it("implements semantic controls and reduced-motion styling", async () => {
    const app = await readFile(path.join(root, "src", "App.tsx"), "utf8");
    const css = await readFile(path.join(root, "src", "report.css"), "utf8");
    assert.match(app, /<main/);
    assert.match(app, /aria-label="Filter scenarios"/);
    assert.match(app, /aria-live="polite"/);
    assert.match(css, /prefers-reduced-motion:\s*reduce/);
  });

  it("never opts into raw React HTML injection", async () => {
    const source = await Promise.all(
      ["App.tsx", "index.tsx", "model.ts"].map((name) =>
        readFile(path.join(root, "src", name), "utf8"),
      ),
    );
    assert.equal(source.join("\n").includes("dangerouslySetInnerHTML"), false);
  });
});
