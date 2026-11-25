import React from "react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import App from "./App";

let assets: any[] = [];
beforeEach(() => {
  assets = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, options?: RequestInit) => {
      const path = String(input);
      let data: any = [];
      if (path === "/api/overview")
        data = {
          counts: {
            assets: assets.length,
            rules: 0,
            connectors: 0,
            vulnerabilities: 0,
          },
          sources: [],
          deliveries: {},
          engine: {},
          setup_required: true,
        };
      if (path === "/api/config/assets") {
        if (options?.method === "POST") {
          expect(
            (options.headers as Record<string, string>)["X-VulnRelay-Request"],
          ).toBe("1");
          const document = JSON.parse(String(options.body));
          assets.push({ id: "asset-one", enabled: true, ...document });
          data = assets[0];
        } else data = assets;
      }
      return { ok: true, json: async () => data };
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("first-run setup loads and an asset can be added through the real form", async () => {
  render(<App />);
  expect(
    await screen.findByText("A few steps to your first alert"),
  ).toBeInTheDocument();
  expect(screen.getByText("Waiting for monitor")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Add your assets/ }));
  fireEvent.click(screen.getByRole("button", { name: "Add asset" }));
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "NGINX production" },
  });
  fireEvent.change(screen.getByLabelText("Vendor"), {
    target: { value: "f5" },
  });
  fireEvent.change(screen.getByLabelText("Product"), {
    target: { value: "nginx" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save asset" }));
  expect(await screen.findByText("NGINX production")).toBeInTheDocument();
  await waitFor(() => expect(assets).toHaveLength(1));
  expect(assets[0].group).toBe("production");
});
