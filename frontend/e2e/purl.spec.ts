import { expect, test } from "@playwright/test";

test("resolve an exact-version package URL and save its reviewed identity", async ({
  page,
  request,
}) => {
  let assetId = "";
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Assets", exact: true })
      .click();
    await page.getByRole("button", { name: "Add asset", exact: true }).click();
    await page.getByLabel("Name", { exact: true }).fill("E2E PURL dependency");
    await page.getByLabel("Match by").selectOption("package");
    await page
      .getByLabel("Package URL (optional)")
      .fill("pkg:npm/%40scope/name@1.2.3");
    await page.getByRole("button", { name: "Use package URL" }).click();
    await expect(page.getByLabel("Package ecosystem")).toHaveValue("npm");
    await expect(page.getByLabel("Package name")).toHaveValue("@scope/name");
    await expect(page.getByLabel("Exact installed version")).toHaveValue(
      "1.2.3",
    );
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/config/assets") &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Save asset" }).click();
    const saved = await (await response).json();
    assetId = saved.id;
    expect(saved.package).toBe("@scope/name");
    expect(saved.version).toBe("1.2.3");
    expect(saved.purl).toBeUndefined();
    await expect(
      page.getByText("E2E PURL dependency", { exact: true }),
    ).toBeVisible();
  } finally {
    if (assetId)
      await request.delete(`/api/config/assets/${assetId}`, {
        headers: { "x-vulnrelay-request": "1" },
      });
  }
});
