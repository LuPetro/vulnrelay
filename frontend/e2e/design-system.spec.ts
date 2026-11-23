import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.use({ timezoneId: "Europe/Vienna", actionTimeout: 20000 });

test("shared design covers every workspace page, editor and both themes", async ({
  page,
}) => {
  test.setTimeout(120000);
  const asset = {
    id: "design-asset",
    name: "Production reverse proxy",
    enabled: true,
    kind: "vendor_product",
    vendor: "haproxy",
    product: "haproxy",
    group: "production",
    environment: "production",
    tags: [],
  };
  const connector = {
    id: "design-connector",
    name: "Operations channel",
    enabled: true,
    kind: "telegram",
    chat_id: "-123456",
    token_env: "TELEGRAM_BOT_TOKEN",
    delivery_schedule: {
      timezone: "Europe/Vienna",
      windows: [{ days: [0, 1, 2, 3, 4], start: "07:00", end: "17:00" }],
    },
  };
  const rule = {
    id: "design-rule",
    name: "Critical production",
    enabled: true,
    groups: ["production"],
    assets: [],
    destinations: [connector.id],
    format: "compact",
    renotify_changes: true,
    condition: { kind: "condition", field: "cvss", op: "gte", value: 9 },
  };
  // Read-only configuration fixtures keep visual checks independent of test ordering.
  for (const [name, data] of Object.entries({
    assets: [asset],
    connectors: [connector],
    rules: [rule],
  }))
    await page.route(`**/api/config/${name}`, (route) =>
      route.fulfill({ json: data }),
    );
  await page.goto("/");
  for (const name of [
    "Assets",
    "Catalog",
    "Notification rules",
    "Connectors",
    "Vulnerabilities",
    "Reports",
    "AI",
    "Settings",
  ]) {
    await page
      .getByRole("navigation")
      .getByRole("button", { name, exact: true })
      .click();
    const main = page.locator("#main-content");
    await expect(main.locator("h1")).toBeVisible();
    await expect(main).toHaveClass("workspace-page");
    expect(
      await main.evaluate((element) => getComputedStyle(element).fontFamily),
    ).toContain("VulnRelay Sans");
    if (name === "Catalog")
      await expect(page.getByLabel("Search catalog")).toBeVisible();
    if (name === "Notification rules") {
      await page.getByRole("button", { name: "Edit", exact: true }).click();
      await expect(
        page.getByRole("button", { name: "Save rule", exact: true }),
      ).toBeVisible();
    }
    if (name === "Vulnerabilities") {
      await page.locator(".cve-row").first().click();
      await expect(
        page.getByRole("button", { name: "Close details" }),
      ).toBeVisible();
    }
    expect(
      (
        await new AxeBuilder({ page })
          .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
          .analyze()
      ).violations,
    ).toEqual([]);
    await page.screenshot({
      path: `test-results/workspace-${name.toLowerCase().replaceAll(" ", "-")}-desktop.png`,
      fullPage: true,
    });
    if (name === "Notification rules")
      await page.getByRole("button", { name: "Cancel", exact: true }).click();
  }
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByLabel("Time zone")).toHaveValue("Europe/Vienna");
  await page.getByRole("button", { name: "Toggle color theme" }).click();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.screenshot({
    path: "test-results/workspace-connector-hours-dark.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  for (const name of [
    "Assets",
    "Catalog",
    "Notification rules",
    "Connectors",
    "Vulnerabilities",
    "Settings",
  ]) {
    await page.setViewportSize({ width: 320, height: 740 });
    await page
      .getByRole("navigation")
      .getByRole("button", { name, exact: true })
      .click();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBeTruthy();
    if (name === "Assets" || name === "Connectors") {
      await page.getByRole("button", { name: "Edit", exact: true }).click();
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBeTruthy();
    }
    await page.screenshot({
      path: `test-results/workspace-${name.toLowerCase().replaceAll(" ", "-")}-mobile-dark.png`,
      fullPage: true,
    });
    if (name === "Assets" || name === "Connectors")
      await page.getByRole("button", { name: "Cancel", exact: true }).click();
  }
});

test("connector hours save through the API and hold queued tests without attempts", async ({
  page,
  request,
}) => {
  test.setTimeout(90000);
  const name = "Schedule acceptance destination";
  const headers = { "X-VulnRelay-Request": "1" };
  let connectorId = "";
  const weekdayNames = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
  ];
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Connectors", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Add connector", exact: true })
      .click();
    await page.getByLabel("Name", { exact: true }).fill(name);
    await page
      .getByLabel("Telegram chat ID or channel username")
      .fill("-123456789");
    await page
      .getByLabel("Send alerts", { exact: true })
      .selectOption("scheduled");
    await page.getByLabel("Time zone", { exact: true }).fill("UTC");
    await page
      .getByRole("button", { name: "Mon–Fri, 07–17", exact: true })
      .click();
    const futureDay = (new Date(Date.now() + 3 * 86400000).getUTCDay() + 6) % 7;
    for (const day of weekdayNames)
      await page.getByLabel(`${day}, window 1`, { exact: true }).uncheck();
    await page
      .getByLabel(`${weekdayNames[futureDay]}, window 1`, { exact: true })
      .check();
    await page
      .getByRole("button", { name: "Save connector", exact: true })
      .click();
    await expect(page.getByText(name, { exact: true })).toBeVisible();
    const configs = await (await request.get("/api/config/connectors")).json();
    const saved = configs.find((item: { name: string }) => item.name === name);
    connectorId = saved.id;
    expect(saved.delivery_schedule).toEqual({
      timezone: "UTC",
      windows: [{ days: [futureDay], start: "07:00", end: "17:00" }],
    });
    expect(
      (
        await request.post(`/api/connectors/${connectorId}/test`, { headers })
      ).ok(),
    ).toBeTruthy();
    expect(
      (await request.post("/api/deliveries/next", { headers })).ok(),
    ).toBeTruthy();
    const status = await (await request.get("/api/queue/status")).json();
    const destination = status.destinations.find(
      (item: { id: string }) => item.id === connectorId,
    );
    expect(destination.status).toBe("outside_schedule");
    expect(destination.queued).toBe(1);
    expect(destination.schedule_timezone).toBe("UTC");
    expect(destination.next_attempt_at).toBeGreaterThan(Date.now() / 1000);
    const history = await (await request.get("/api/deliveries")).json();
    expect(
      history.find(
        (item: { connector_id: string }) => item.connector_id === connectorId,
      ).attempts,
    ).toBe(0);
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(
      page.getByText("Outside delivery hours", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    await expect(page.getByLabel("Time zone", { exact: true })).toHaveValue(
      "UTC",
    );
    await page
      .getByLabel("Send alerts", { exact: true })
      .selectOption("always");
    await page
      .getByRole("button", { name: "Save connector", exact: true })
      .click();
    const unrestricted = await (
      await request.get("/api/config/connectors")
    ).json();
    expect(
      unrestricted.find((item: { id: string }) => item.id === connectorId)
        .delivery_schedule,
    ).toBeNull();
    const reopened = await (await request.get("/api/queue/status")).json();
    expect(
      reopened.destinations.find(
        (item: { id: string }) => item.id === connectorId,
      ).status,
    ).toBe("ready");
  } finally {
    if (connectorId) {
      await request.post("/api/queue/clear", {
        headers,
        data: { before: Date.now() / 1000, connector_id: connectorId },
      });
      await request.delete(`/api/config/connectors/${connectorId}`, {
        headers,
      });
    }
  }
});
