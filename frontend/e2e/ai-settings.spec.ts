import { expect, test } from "@playwright/test";

test("AI is optional and saved provider settings can be tested", async ({
  page,
  request,
}) => {
  const headers = { "x-vulnrelay-request": "1" };
  const before = await (await request.get("/api/ai/settings")).json();
  try {
    await page.route("**/api/ai/test", (route) =>
      route.fulfill({
        json: {
          ok: true,
          summary: "A fictional issue.",
          usage: { day_utc: "2026-11-23", requests: 1 },
        },
      }),
    );
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "AI", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "Optional AI summaries" }),
    ).toBeVisible();
    await expect(
      page.getByLabel("Include AI summaries in alerts"),
    ).not.toBeChecked();
    await page.getByLabel("AI API protocol").selectOption("openai_compatible");
    await page.getByLabel("Model name").fill("example/model");
    await page.getByLabel("Summary language").fill("German");
    await expect(
      page.getByRole("button", { name: "Test connection" }),
    ).toBeDisabled();
    await page.getByRole("button", { name: "Save AI settings" }).click();
    await expect(
      page.getByRole("status").getByText("AI settings saved."),
    ).toBeVisible();
    const stored = await (await request.get("/api/ai/settings")).json();
    expect(stored.settings).toMatchObject({
      enabled: false,
      provider: "openai_compatible",
      model: "example/model",
      language: "German",
    });
    await page.getByRole("button", { name: "Test connection" }).click();
    await expect(
      page.getByText(
        "Connection succeeded using a fictional test description.",
      ),
    ).toBeVisible();
    await expect(
      page.getByText("AI test output (unverified): A fictional issue."),
    ).toBeVisible();
  } finally {
    await request.put("/api/ai/settings", { headers, data: before.settings });
  }
});
