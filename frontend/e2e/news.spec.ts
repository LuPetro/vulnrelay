import { expect, test } from "@playwright/test";

test("news subscription, attribution and filtering work on mobile", async ({
  page,
}) => {
  let settings = {
    enabled: false,
    sources: ["cisa"],
    notifications: false,
    destinations: [] as string[],
    categories: ["security", "vulnerability"],
  };
  await page.route("**/api/config/connectors", (route) =>
    route.fulfill({
      json: [{ id: "telegram", name: "Security channel", enabled: true }],
    }),
  );
  await page.route("**/api/news/settings", async (route) => {
    settings = route.request().postDataJSON();
    await route.fulfill({ json: settings });
  });
  await page.route("**/api/news", (route) =>
    route.fulfill({
      json: {
        settings,
        sources: [
          { id: "cisa", name: "CISA Advisories", last_success: 1800000000 },
        ],
        items: [
          {
            id: "article",
            source: "cisa",
            title: "Example zero-day vulnerability",
            url: "https://example.org/security",
            category: "vulnerability",
            published: "2026-11-25T08:00:00+00:00",
            discovered: 1800000000,
            highlight: "Headline mentions a zero-day",
          },
        ],
      },
    }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.getByRole("button", { name: "News", exact: true }).click();
  await expect(
    page.getByRole("link", { name: /Example zero-day vulnerability/ }),
  ).toHaveAttribute("href", "https://example.org/security");
  await expect(page.getByText("Headline mentions a zero-day")).toBeVisible();
  await page.getByLabel("Enable news collection").check();
  await page.getByLabel("Send new articles to connectors").check();
  await page.getByLabel("Security channel").check();
  await page.getByRole("button", { name: "Save news settings" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "News settings saved" }),
  ).toBeVisible();
  expect(settings.notifications).toBe(true);
  expect(settings.destinations).toEqual(["telegram"]);
  await page.getByLabel("Search headlines").fill("not a match");
  await expect(page.getByText("Example zero-day vulnerability")).toHaveCount(0);
});
