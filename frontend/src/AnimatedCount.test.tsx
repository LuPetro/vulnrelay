import React from "react";
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import AnimatedCount, { formatCount } from "./AnimatedCount";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

test("compact display keeps precise accessible counts and rolls only actual increases", () => {
  vi.useFakeTimers();
  const { container, rerender } = render(<AnimatedCount value={999} motion />);
  expect(container.querySelector(".count-current")?.textContent).toBe("999");
  expect(container.querySelector(".count-previous")).toBeNull();
  rerender(<AnimatedCount value={1234} motion />);
  expect(container.querySelector(".count-current")?.textContent).toMatch(
    /^1[,.]2k$/,
  );
  expect(container.querySelector(".count-previous")?.textContent).toBe("999");
  expect(container.querySelector(".count-accessible")?.textContent).toBe(
    (1234).toLocaleString(),
  );
  rerender(<AnimatedCount value={1250} motion />);
  expect(container.querySelector(".count-accessible")?.textContent).toBe(
    (1250).toLocaleString(),
  );
  act(() => vi.advanceTimersByTime(701));
  expect(container.querySelector(".count-previous")).toBeNull();
  rerender(<AnimatedCount value={1251} motion={false} />);
  expect(container.querySelector(".count-previous")).toBeNull();
  rerender(<AnimatedCount value={1200} motion />);
  expect(container.querySelector(".count-previous")).toBeNull();
});

test("number formatting follows the chosen k boundary and locale", () => {
  expect(formatCount(0, "de-DE")).toBe("0");
  expect(formatCount(999, "de-DE")).toBe("999");
  expect(formatCount(1000, "de-DE")).toBe("1k");
  expect(formatCount(1234, "de-DE")).toBe("1,2k");
  expect(formatCount(1234, "en-US")).toBe("1.2k");
});
