import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";

test("configure an asset, destination and rule, explain the match, then inspect a failed test safely", async ({
  page,
}) => {
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
    page.getByText(/Telegram token environment variable is missing or invalid/),
  ).toBeVisible();
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("retry", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText("A few steps to your first alert")).toHaveCount(
    0,
  );

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
