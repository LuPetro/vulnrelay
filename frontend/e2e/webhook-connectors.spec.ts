import { expect, test } from "@playwright/test";

test("configure Discord and Slack without entering their secret URLs", async ({
  page,
  request,
}) => {
  const ids: string[] = [];
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Connectors", exact: true })
      .click();
    for (const [kind, variable, name] of [
      ["discord", "DISCORD_WEBHOOK_URL", "E2E Discord"],
      ["slack", "SLACK_WEBHOOK_URL", "E2E Slack"],
    ]) {
      await page
        .getByRole("button", { name: "Add connector", exact: true })
        .click();
      await page.getByLabel("Name", { exact: true }).fill(name);
      await page
        .getByRole("combobox", { name: "Connector type" })
        .selectOption(kind);
      await expect(page.getByLabel("Webhook environment variable")).toHaveValue(
        variable,
      );
      await expect(
        page.getByText(/The URL is never saved in this form/),
      ).toBeVisible();
      const response = page.waitForResponse(
        (r) =>
          r.url().endsWith("/api/config/connectors") &&
          r.request().method() === "POST",
      );
      await page
        .getByRole("button", { name: "Save connector", exact: true })
        .click();
      const saved = await (await response).json();
      ids.push(saved.id);
      expect(saved.kind).toBe(kind);
      expect(saved.webhook_env).toBe(variable);
      await expect(page.getByText(name, { exact: true })).toBeVisible();
    }
  } finally {
    for (const id of ids) {
      await request.delete(`/api/config/connectors/${id}`, {
        headers: { "x-vulnrelay-request": "1" },
      });
    }
  }
});
