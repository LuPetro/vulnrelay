import { expect, test } from "@playwright/test";

test("configure push destinations without entering their credentials", async ({
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
    for (const [kind, prefix, name] of [
      ["ntfy", "NTFY", "E2E ntfy"],
      ["gotify", "GOTIFY", "E2E Gotify"],
    ]) {
      await page
        .getByRole("button", { name: "Add connector", exact: true })
        .click();
      await page.getByLabel("Name", { exact: true }).fill(name);
      await page.getByLabel("Connector type").selectOption(kind);
      await expect(
        page.getByLabel("Push server URL environment variable"),
      ).toHaveValue(`VULNRELAY_${prefix}_URL`);
      await expect(
        page.getByLabel("Push token environment variable"),
      ).toHaveValue(`VULNRELAY_${prefix}_TOKEN`);
      if (kind === "ntfy") {
        await page.getByLabel("ntfy topic").fill("test-alerts");
        await expect(page.getByText(/Public ntfy topics/)).toBeVisible();
      }
      const response = page.waitForResponse(
        (r) =>
          r.url().endsWith("/api/config/connectors") &&
          r.request().method() === "POST",
      );
      await page.getByRole("button", { name: "Save connector" }).click();
      const saved = await (await response).json();
      ids.push(saved.id);
      expect(saved.kind).toBe(kind);
      expect(saved.webhook_env).toBe(`VULNRELAY_${prefix}_URL`);
      expect(saved.push_token_env).toBe(`VULNRELAY_${prefix}_TOKEN`);
      if (kind === "ntfy") expect(saved.ntfy_topic).toBe("test-alerts");
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
