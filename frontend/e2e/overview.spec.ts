import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";

test("overview shows honest state, motion controls, branding and responsive layouts", async ({
  page,
}) => {
  test.setTimeout(90000);
  const now = Math.floor(Date.now() / 1000);
  const snapshot = {
    counts: { assets: 3, rules: 1, connectors: 1, vulnerabilities: 1328 },
    engine: { delivery_heartbeat: now },
    setup_required: false,
    deliveries: { sent: 12, pending: 2, failed: 0 },
    sources: [
      { source: "nvd", last_success_at: now - 300, last_error: "" },
      { source: "cisa_kev", last_success_at: now - 600, last_error: "" },
      { source: "epss", last_success_at: now - 3600, last_error: "" },
    ],
  };
  const inventory = [
    {
      id: "one",
      name: "NGINX",
      group: "Production",
      environment: "production",
      enabled: true,
    },
    {
      id: "two",
      name: "PostgreSQL",
      group: "Production",
      environment: "production",
      enabled: true,
    },
    {
      id: "three",
      name: "Ubuntu",
      group: "Homelab",
      environment: "homelab",
      enabled: false,
    },
  ];
  // Read-only UI fixtures: no inventory writes, credentials or external delivery.
  await page.route("**/api/overview", (r) => r.fulfill({ json: snapshot }));
  await page.route("**/api/config/assets", (r) =>
    r.fulfill({ json: inventory }),
  );
  await page.route("**/api/config/rules", (r) =>
    r.fulfill({ json: [{ id: "rule", name: "Production", enabled: true }] }),
  );
  await page.route("**/api/config/connectors", (r) =>
    r.fulfill({
      json: [{ id: "telegram", name: "Security channel", enabled: true }],
    }),
  );
  await page.route("**/api/deliveries", (r) =>
    r.fulfill({
      json: [
        {
          id: "example-delivery",
          connector_id: "telegram",
          state: "sent",
          attempts: 1,
          created_at: now - 120,
        },
      ],
    }),
  );
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.goto("/");
  await expect(
    page.getByText("Recent heartbeat", { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("button", { name: /^Enabled assets/ })
      .getByText("2", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Sent messages", { exact: true })).toBeVisible();
  await expect(page.getByText("Manual", { exact: true })).toBeVisible();
  await expect(
    page.getByText("How alerts flow · illustrative animation"),
  ).toBeVisible();
  const mark = await page.request.get("/brand/vulnrelay-mark.svg");
  expect(mark.headers()["content-type"]).toContain("image/svg+xml");
  expect(
    (await page.request.get("/favicon.svg")).headers()["content-type"],
  ).toContain("image/svg+xml");
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "signal-transit",
  );
  await page
    .getByRole("button", { name: "Pause overview animation", exact: true })
    .click();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "none",
  );
  await page.reload();
  await expect(
    page.getByRole("button", {
      name: "Resume overview animation",
      exact: true,
    }),
  ).toBeVisible();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "none",
  );
  await page.screenshot({
    path: "test-results/overview-modern-desktop.png",
    fullPage: true,
  });
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.getByRole("button", { name: "Toggle color theme" }).click();
  await page.screenshot({
    path: "test-results/overview-modern-dark.png",
    fullPage: true,
  });
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.getByRole("button", { name: "Toggle color theme" }).click();
  await page
    .getByRole("button", { name: "Resume overview animation", exact: true })
    .click();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "signal-transit",
  );
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(
    page.getByRole("button", { name: "Motion reduced by system preference" }),
  ).toBeDisabled();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "none",
  );

  snapshot.engine.delivery_heartbeat = now - 600;
  snapshot.sources[0].last_error = "Source temporarily unavailable";
  snapshot.deliveries.failed = 1;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Stale heartbeat", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Recent heartbeat", { exact: true })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: /1 source error/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: /1 failed message/ }).click();
  await expect(
    page.getByRole("heading", { name: "Connectors", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Overview", exact: true })
    .click();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByText("Stale heartbeat", { exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
  await page.screenshot({
    path: "test-results/overview-modern-mobile.png",
    fullPage: true,
  });
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.setViewportSize({ width: 1000, height: 560 });
  await page.goto("/brand/vulnrelay-brand-sheet.svg");
  await page.screenshot({ path: "test-results/vulnrelay-logo.png" });
});
