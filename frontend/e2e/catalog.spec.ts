import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";

test.use({ actionTimeout: 15000 });
test.afterEach(async ({ request }) => {
  // Keep retries independent while preserving fixtures owned by other scenarios.
  const assets = await (await request.get("/api/config/assets")).json();
  for (const asset of assets.filter(
    (a: any) => a.group === "acceptance-stack",
  )) {
    await request.delete(`/api/config/assets/${asset.id}`, {
      headers: { "X-VulnRelay-Request": "1" },
    });
  }
});

test("assemble a pack, review safely, reuse duplicates and keep manual entry", async ({
  page,
}) => {
  test.setTimeout(120000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");
  await page.getByRole("button", { name: "Explore the catalog" }).click();
  await expect(
    page.getByRole("heading", { name: "Your stack. A few clicks away." }),
  ).toBeVisible();
  await page.getByLabel("Search catalog").fill("postgres");
  await expect(
    page.getByRole("button", { name: "Select PostgreSQL", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Select NGINX", exact: true }),
  ).toHaveCount(0);
  await page.getByLabel("Search catalog").fill("does-not-exist");
  await expect(page.getByText("No matching entries")).toBeVisible();
  await page
    .getByRole("button", { name: "Environment packs", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Select Linux essentials" }),
  ).toBeVisible();
  await page.screenshot({ path: "test-results/catalog-packs-desktop.png" });
  await page.getByRole("button", { name: "Select Linux essentials" }).click();
  await page
    .getByRole("button", { name: "Remove Linux kernel", exact: true })
    .click();
  await page.getByRole("button", { name: "Technologies", exact: true }).click();
  await page.getByLabel("Search catalog").fill("nginx");
  await page.getByRole("button", { name: "Select NGINX", exact: true }).click();
  await page
    .getByLabel("Asset group", { exact: true })
    .fill("acceptance-stack");
  await page.getByLabel("Environment", { exact: true }).selectOption("staging");
  const before = (await (await page.request.get("/api/config/assets")).json())
    .length;
  await page
    .getByRole("button", { name: "Review selection", exact: true })
    .click();
  await expect(
    page.getByText("4 new · 0 already present", { exact: true }),
  ).toBeVisible();
  expect(
    (await (await page.request.get("/api/config/assets")).json()).length,
  ).toBe(before);
  // Changing context invalidates the old preview before a write is allowed.
  await page.getByLabel("Environment", { exact: true }).selectOption("homelab");
  await expect(
    page.getByRole("button", { name: "Review selection", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Review selection", exact: true })
    .click();
  await page.getByRole("button", { name: "Add 4 assets", exact: true }).click();
  await expect(
    page.getByText("4 assets added · 0 already present", { exact: true }),
  ).toBeVisible();
  const after = await (await page.request.get("/api/config/assets")).json();
  expect(after.length).toBe(before + 4);
  expect(
    after
      .filter((a: any) => a.group === "acceptance-stack")
      .every((a: any) => a.environment === "homelab"),
  ).toBeTruthy();
  await page
    .getByRole("button", { name: "Environment packs", exact: true })
    .click();
  await page.getByRole("button", { name: "Select Linux essentials" }).click();
  await page
    .getByRole("button", { name: "Remove Linux kernel", exact: true })
    .click();
  await page.getByRole("button", { name: "Technologies", exact: true }).click();
  await page.getByLabel("Search catalog").fill("nginx");
  await page.getByRole("button", { name: "Select NGINX", exact: true }).click();
  await page
    .getByRole("button", { name: "Review selection", exact: true })
    .click();
  await expect(
    page.getByText("0 new · 4 already present", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Add 0 assets", exact: true }).click();
  await expect(
    page.getByText("0 assets added · 4 already present", { exact: true }),
  ).toBeVisible();
  expect(
    (await (await page.request.get("/api/config/assets")).json()).length,
  ).toBe(before + 4);
  await page.getByRole("button", { name: "View assets", exact: true }).click();
  await page.getByLabel("Search assets").fill("missing-inventory");
  await expect(
    page.getByText("No matching assets", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Search assets").fill("acceptance-stack");
  await expect(page.locator(".entry-row")).toHaveCount(4);
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  await expect(page.getByLabel("Vendor", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.reload();
  await expect(
    page.getByText("Waiting for monitor", { exact: true }),
  ).toBeVisible();
  await page.screenshot({ path: "test-results/overview-desktop.png" });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Catalog", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Select NGINX", exact: true }),
  ).toBeVisible();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.getByRole("button", { name: "Toggle color theme" }).click();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.screenshot({ path: "test-results/catalog-dark-desktop.png" });
  await page.getByRole("button", { name: "Toggle color theme" }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page
    .getByRole("button", { name: "Environment packs", exact: true })
    .click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.screenshot({ path: "test-results/catalog-mobile.png" });
  await page.getByRole("button", { name: "Select Linux essentials" }).click();
  await expect(
    page.getByRole("link", { name: "Review 4 selected" }),
  ).toBeInViewport();
  await page.getByRole("link", { name: "Review 4 selected" }).click();
  await expect(
    page.getByLabel("Asset group", { exact: true }),
  ).toBeInViewport();
  await page.screenshot({ path: "test-results/catalog-mobile-selection.png" });
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
});
