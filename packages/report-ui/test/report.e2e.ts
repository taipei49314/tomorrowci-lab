import { expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reportUrl = pathToFileURL(path.join(packageRoot, ".tmp", "browser-fixture", "report.html")).href;

test("interactive report renders verified data, filters, and keeps XSS inert", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  await page.goto(reportUrl);

  await expect(page).toHaveTitle(/TomorrowCI Report browser-fixture/);
  await expect(page.getByRole("heading", { name: /Run browser-fixture/ })).toBeVisible();
  await expect(page.getByText("AUTHORIZED BY VERIFIED FRONTIER")).toBeVisible();
  await expect(page.getByText("Showing 3 of 3")).toBeVisible();
  await page.getByRole("button", { name: "Needs attention" }).click();
  await expect(page.getByText("Showing 2 of 3")).toBeVisible();
  await expect(page.getByRole("heading", { name: "baseline" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "node22" })).toBeVisible();

  expect(await page.evaluate(() => (window as typeof window & { __tomorrowciXss?: boolean }).__tomorrowciXss)).toBeUndefined();
  await expect(page.locator("img[data-xss], script[data-xss]")).toHaveCount(0);
  expect(consoleErrors).toEqual([]);
});

test("keyboard, accessibility, and reduced motion gates", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(reportUrl);
  await page.getByRole("button", { name: "All" }).focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Needs attention" })).toBeFocused();

  const axePath = path.join(packageRoot, "node_modules", "axe-core", "axe.min.js");
  await page.addScriptTag({ path: axePath });
  const violations = await page.evaluate(async () => {
    const result = await (window as typeof window & { axe: { run: (root: Document) => Promise<{ violations: Array<{ impact: string | null; id: string }> }> } }).axe.run(document);
    return result.violations;
  });
  expect(violations).toEqual([]);

  const duration = await page.getByRole("button", { name: "All" }).evaluate((element) =>
    Number.parseFloat(getComputedStyle(element).transitionDuration) || 0,
  );
  expect(duration).toBeLessThanOrEqual(0.001);
});

test("narrow viewport stays readable without document overflow", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(reportUrl);
  await expect(page.getByRole("heading", { name: /Run browser-fixture/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Scenario order" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("no-JavaScript fallback retains the core evidence", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 800, height: 900 } });
  const page = await context.newPage();
  await page.goto(reportUrl);
  const fallback = page.locator("#no-js-report");
  await expect(fallback.getByRole("heading", { name: /Run browser-fixture/ })).toBeVisible();
  await expect(fallback.getByText("node22", { exact: true }).first()).toBeVisible();
  await expect(fallback.getByText("Replay attempts")).toBeVisible();
  await expect(fallback.getByText("BLOCKED").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Needs attention" })).toHaveCount(0);
  await context.close();
});
