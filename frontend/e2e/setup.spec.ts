import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";

test("configure an asset, destination and rule, explain the match, then inspect a failed test safely", async ({
  page,
}) => {
  // Full acceptance flow plus accessibility checks on resource-limited hosts.
  test.setTimeout(120000);
  await page.goto("/");
  await expect(page.getByText("A few steps to your first alert")).toBeVisible();
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  await page.getByRole("button", { name: /Add your assets/ }).click();
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  await page
    .getByLabel("Name", { exact: true })
    .fill("Example production server");
  await page.getByLabel("Vendor", { exact: true }).fill("example");
  await page.getByLabel("Product", { exact: true }).fill("server");
  await page.getByRole("button", { name: "Save asset", exact: true }).click();
  await expect(
    page.getByText("Example production server", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  await page.getByLabel("Name", { exact: true }).fill("Conflicting version");
  await page
    .getByRole("combobox", { name: "Match by", exact: true })
    .selectOption("cpe");
  await page
    .getByLabel("CPE 2.3", { exact: true })
    .fill("cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*");
  await page.getByLabel("Installed version (optional)").fill("2.0");
  await page.getByRole("button", { name: "Save asset", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("version conflicts");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(
    page.getByText("Conflicting version", { exact: true }),
  ).toHaveCount(0);

  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await page.getByLabel("Name", { exact: true }).fill("Security channel");
  await page
    .getByLabel("Telegram chat ID or channel username")
    .fill("-1001234567890");
  await page
    .getByRole("button", { name: "Save connector", exact: true })
    .click();
  await expect(
    page.getByText("Security channel", { exact: true }),
  ).toBeVisible();

  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Notification rules", exact: true })
    .click();
  await page.getByRole("button", { name: "Add rule", exact: true }).click();
  await page.getByLabel("Name", { exact: true }).fill("Critical production");
  await page.getByLabel("Security channel", { exact: true }).check();
  await page.getByRole("button", { name: "Save rule", exact: true }).click();
  await page.getByRole("button", { name: "Test rule", exact: true }).click();
  await expect(page.getByText("CVE-2026-1234", { exact: true })).toBeVisible();
  await expect(page.getByText("Matched", { exact: true })).toBeVisible();

  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Settings", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Evaluate saved intelligence" })
    .click();
  await expect(page.getByRole("status")).toContainText("Matching alerts added");
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await page.getByRole("button", { name: "Process next message" }).click();
  await expect(page.getByText("failed", { exact: true })).toBeVisible();
  await expect(
    page
      .locator(".delivery-row")
      .getByText(/Telegram token environment variable is missing or invalid/),
  ).toBeVisible();
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("retry", { exact: true })).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Notification rules", exact: true })
    .click();
  await page.getByRole("button", { name: "Disable", exact: true }).click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await expect
    .poll(
      async () => {
        const processNext = page.getByRole("button", {
          name: "Process next message",
        });
        await processNext.click();
        await expect(processNext).toBeEnabled({ timeout: 15000 });
        return page.getByText("cancelled", { exact: true }).count();
      },
      { timeout: 30000 },
    )
    .toBe(1);
  await expect(page.getByText(/Rule disabled or removed/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Retry", exact: true }),
  ).toHaveCount(0);
  await page.reload();
  await expect(page.getByText("A few steps to your first alert")).toHaveCount(
    0,
  );

  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Vulnerabilities", exact: true })
    .click();
  await page.getByRole("button", { name: /CVE-2026-1234/ }).click();
  await page.getByRole("button", { name: "Load OpenCVE details" }).click();
  await expect(
    page.getByRole("link", { name: "View OpenCVE record ↗" }),
  ).toBeVisible();
  await expect(
    page.getByText("CVSS assessment: NVD", { exact: true }),
  ).toBeVisible();
  await page.getByText("Separate OpenCVE assessment", { exact: true }).click();
  await expect(page.getByText(/"cvss": 8.2/)).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Overview", exact: true })
    .click();

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("heading", { name: "Your security, on watch." }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
});
