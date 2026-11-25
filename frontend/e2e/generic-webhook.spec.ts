import { expect, test } from "@playwright/test";

test("configure a generic webhook through environment references", async ({
  page,
  request,
}) => {
  let id = "";
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Connectors", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Add connector", exact: true })
      .click();
    await page.getByLabel("Name", { exact: true }).fill("E2E webhook");
    await page.getByLabel("Connector type").selectOption("webhook");
    await expect(page.getByLabel("Webhook environment variable")).toHaveValue(
      "VULNRELAY_WEBHOOK_URL",
    );
    await expect(
      page.getByLabel("Signing key environment variable"),
    ).toHaveValue("VULNRELAY_WEBHOOK_KEY");
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/config/connectors") &&
        r.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Save connector", exact: true })
      .click();
    const saved = await (await response).json();
    id = saved.id;
    expect(saved).toMatchObject({
      kind: "webhook",
      webhook_env: "VULNRELAY_WEBHOOK_URL",
    });
    await expect(page.getByText("E2E webhook", { exact: true })).toBeVisible();
  } finally {
    if (id)
      await request.delete(`/api/config/connectors/${id}`, {
        headers: { "x-vulnrelay-request": "1" },
      });
  }
});
