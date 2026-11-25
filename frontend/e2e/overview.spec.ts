import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";
import { waitForUiTransitions } from "./transitions";

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
      {
        source: "nvd",
        last_success_at: now - 300,
        last_error: "",
        next_attempt_at: now + 120,
        retry_scheduled: false,
      },
      { source: "cisa_kev", last_success_at: now - 600, last_error: "" },
      { source: "epss", last_success_at: now - 3600, last_error: "" },
    ],
  };
  const queue = {
    as_of: now,
    queued: 2,
    ready: 0,
    sending: 0,
    last_sent_at: now - 120,
    next_attempt_at: now + 30,
    counts: snapshot.deliveries,
    destinations: [
      {
        id: "telegram",
        name: "Security channel",
        kind: "telegram",
        status: "rate_limited",
        queued: 2,
        sending: 0,
        min_interval_seconds: 3.1,
        next_attempt_at: now + 30,
        rate_limited_until: now + 30,
      },
    ],
  };
  Object.assign(snapshot, { queue });
  let cleared = 0;
  await page.route("**/api/queue/status", (r) => r.fulfill({ json: queue }));
  await page.route("**/api/queue/clear", (r) => {
    expect(r.request().postDataJSON()).toEqual({ before: now });
    cleared++;
    queue.queued = 0;
    queue.destinations = [];
    snapshot.deliveries.pending = 0;
    return r.fulfill({ json: { cleared: 2, before: now } });
  });
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
  await expect(page.locator("#main-content")).toHaveClass("overview-workspace");
  await page.evaluate(async () => {
    await document.fonts.load('500 14px "VulnRelay Sans"');
    await document.fonts.load('400 12px "VulnRelay Mono"');
  });
  expect(
    await page.evaluate(() =>
      document.fonts.check('500 14px "VulnRelay Sans"'),
    ),
  ).toBeTruthy();
  expect(
    await page.evaluate(() =>
      document.fonts.check('400 12px "VulnRelay Mono"'),
    ),
  ).toBeTruthy();
  await expect(
    page.getByText("Recent heartbeat", { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("button", { name: /^Enabled assets/ })
      .getByText("2", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Sent messages", { exact: true })).toBeVisible();
  for (const provider of ["OpenCVE", "OSV"]) {
    await expect(
      page
        .getByRole("region", { name: "Intelligence sources" })
        .getByRole("listitem")
        .filter({ hasText: provider })
        .getByText("Manual", { exact: true }),
    ).toBeVisible();
  }
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
  await expect(page.locator(".signal-packet").first()).toHaveCSS(
    "animation-name",
    "signal-transit",
  );
  const packet = page.locator(".relay-desktop .signal-packet").first();
  const initialPosition = await packet.evaluate(
    (element) => getComputedStyle(element).offsetDistance,
  );
  await expect
    .poll(() =>
      packet.evaluate((element) => getComputedStyle(element).offsetDistance),
    )
    .not.toBe(initialPosition);
  const noHold = await packet.evaluate((element) => {
    const animation = element.getAnimations()[0];
    animation.pause();
    const progress = [20, 120].map((time) => {
      animation.currentTime = time;
      return parseFloat(getComputedStyle(element).offsetDistance);
    });
    return progress;
  });
  expect(noHold[1]).toBeGreaterThan(noHold[0]);
  await expect(packet).toHaveCSS("animation-duration", "4.2s");
  // Loading indicators keep moving during ingress, before a packet reaches the core.
  for (const selector of [
    ".relay-core-scan",
    ".relay-rule-scan",
    ".relay-output-sheet",
  ]) {
    const frames = await page
      .locator(`.relay-desktop ${selector}`)
      .first()
      .evaluate((element) => {
        const animation = element.getAnimations()[0];
        animation.pause();
        return [50, 150].map((time) => {
          animation.currentTime = time;
          const style = getComputedStyle(element);
          return [style.strokeDashoffset, style.scale, style.translate].join(
            "/",
          );
        });
      });
    expect(frames[0]).not.toBe(frames[1]);
  }
  const ingress = page.locator(".relay-desktop .packet-input");
  const centers = await ingress.evaluateAll((elements) => {
    for (const element of elements)
      for (const animation of element.getAnimations()) {
        animation.pause();
        animation.currentTime = 4200 * 0.37999;
      }
    return elements.map((element) => {
      const box = element.getBoundingClientRect();
      return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
    });
  });
  expect(centers).toHaveLength(3);
  for (const point of centers) {
    expect(Math.abs(point.x - centers[0].x)).toBeLessThan(1);
    expect(Math.abs(point.y - centers[0].y)).toBeLessThan(1);
  }
  expect(
    await page
      .locator(".relay-desktop")
      .evaluate((element) =>
        element.lastElementChild?.classList.contains("relay-packets"),
      ),
  ).toBeTruthy();
  await page
    .getByRole("button", { name: "Pause overview animation", exact: true })
    .click();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "none",
  );
  await expect(page.locator(".relay-rule-scan").first()).toHaveCSS(
    "animation-name",
    "none",
  );
  await expect(page.locator(".relay-output-sheet").first()).toHaveCSS(
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
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await waitForUiTransitions(page);
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
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await waitForUiTransitions(page);
  await page
    .getByRole("button", { name: "Resume overview animation", exact: true })
    .click();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "signal-transit",
  );
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", {
      configurable: true,
      value: true,
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.locator(".overview-page")).toHaveAttribute(
    "data-motion",
    "paused",
  );
  await expect(page.locator(".signal-packet").first()).toHaveCSS(
    "animation-name",
    "none",
  );
  await page.evaluate(() => {
    Reflect.deleteProperty(document, "hidden");
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.locator(".overview-page")).toHaveAttribute(
    "data-motion",
    "running",
  );
  snapshot.deliveries.sent = 1234;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator(".animated-count .count-current")).toHaveText(
    /1[,.]2k/,
  );
  snapshot.deliveries.sent = 1235;
  const preciseCount = await page.evaluate(() => (1235).toLocaleString());
  await expect(page.locator(".animated-count")).toHaveAttribute(
    "title",
    preciseCount,
    { timeout: 10000 },
  );
  await expect(
    page.getByText("Telegram rate limit", { exact: true }),
  ).toBeVisible();
  page.once("dialog", (dialog) => dialog.dismiss());
  await page
    .getByRole("button", { name: "Clear waiting messages", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Clear waiting messages", exact: true }),
  ).toBeEnabled();
  expect(cleared).toBe(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page
    .getByRole("button", { name: "Clear waiting messages", exact: true })
    .click();
  await expect.poll(() => cleared).toBe(1);
  await expect(
    page
      .getByRole("region", { name: "Delivery queue" })
      .getByText(/^No waiting messages\./),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Clear waiting messages", exact: true }),
  ).toBeDisabled();
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(
    page.getByRole("button", { name: "Motion reduced by system preference" }),
  ).toBeDisabled();
  await expect(page.locator(".signal-flow").first()).toHaveCSS(
    "animation-name",
    "none",
  );

  snapshot.engine.delivery_heartbeat = now - 600;
  snapshot.sources[0].last_error =
    "NVD request timed out; check connectivity or retry later.";
  snapshot.sources[0].retry_scheduled = true;
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
  await expect(
    page.getByText(`Last sync failed: ${snapshot.sources[0].last_error}`, {
      exact: true,
    }),
  ).toBeVisible();
  const nvdRow = page
    .locator(".overview-source")
    .filter({ hasText: "CVE records & severity" });
  await expect(
    nvdRow.getByText("Retry scheduled", { exact: true }),
  ).toBeVisible();
  await expect(nvdRow.getByText(/^Last success:/)).toBeVisible();
  await expect(nvdRow.getByText(/^Retry scheduled:/)).toBeVisible();
  await page.getByRole("button", { name: /1 failed message/ }).click();
  await expect(
    page.getByRole("heading", { name: "Connectors", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#main-content")).not.toHaveClass(
    "overview-workspace",
  );
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Overview", exact: true })
    .click();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator(".relay-mobile")).toBeVisible();
  await expect(page.locator(".relay-desktop")).not.toBeVisible();
  await page.setViewportSize({ width: 320, height: 740 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
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
  snapshot.sources[0].last_error = "";
  snapshot.sources[0].retry_scheduled = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(nvdRow.getByText("Synced", { exact: true })).toBeVisible();
  await expect(nvdRow.getByText(/^Last sync failed:/)).toHaveCount(0);
  await expect(nvdRow.getByText(/^Next sync:/)).toBeVisible();
  await page.setViewportSize({ width: 1000, height: 560 });
  await page.goto("/brand/vulnrelay-brand-sheet.svg");
  await page.screenshot({ path: "test-results/vulnrelay-logo.png" });
});
