import { expect, test } from "@playwright/test";

test("review and import package URLs without creating duplicate assets", async ({
  page,
  request,
}) => {
  const ids: string[] = [];
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Assets", exact: true })
      .click();
    await page.getByRole("button", { name: "Import package list" }).click();
    const panel = page.getByRole("region", { name: "Import package list" });
    await panel.getByLabel("Asset group").fill("e2e-package-batch");
    await panel
      .getByLabel("Package URLs")
      .fill(
        "pkg:npm/next@15.1.0\npkg:pypi/django@5.1.0\npkg:pypi/Django@5.1.0",
      );
    await panel.getByRole("button", { name: "Review package list" }).click();
    await expect(
      panel.getByText("2 new · 1 already present or repeated"),
    ).toBeVisible();
    await panel.getByLabel("Environment (optional)").fill("staging");
    await expect(
      panel.getByRole("button", { name: "Import packages" }),
    ).toBeDisabled();
    await panel.getByRole("button", { name: "Review package list" }).click();
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/packages/import") &&
        r.request().method() === "POST",
    );
    await panel.getByRole("button", { name: "Import packages" }).click();
    const saved = await (await response).json();
    ids.push(...saved.created.map((item: { id: string }) => item.id));
    expect(saved.created).toHaveLength(2);
    expect(saved.existing).toHaveLength(1);
    await expect(panel.getByText(/Imported 2 assets/)).toBeVisible();
  } finally {
    for (const id of ids) {
      await request.delete(`/api/config/assets/${id}`, {
        headers: { "x-vulnrelay-request": "1" },
      });
    }
  }
});
