import { afterEach, expect, test } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import ConnectorSchedule, {
  type DeliverySchedule,
  scheduleDescription,
} from "./ConnectorSchedule";

afterEach(cleanup);
function Form() {
  const [value, setValue] = useState<DeliverySchedule | null>(null);
  return (
    <form>
      <ConnectorSchedule value={value} onChange={setValue} />
      <output data-testid="value">{JSON.stringify(value)}</output>
    </form>
  );
}
function configured() {
  return JSON.parse(screen.getByTestId("value").textContent || "null");
}

test("schedule controls preserve unrestricted defaults, support workdays and retain a draft", () => {
  render(<Form />);
  expect(configured()).toBeNull();
  fireEvent.change(screen.getByLabelText("Send alerts"), {
    target: { value: "scheduled" },
  });
  expect(configured().windows).toEqual([
    { days: [0, 1, 2, 3, 4], start: "07:00", end: "17:00" },
  ]);
  fireEvent.change(screen.getByLabelText("Time zone"), {
    target: { value: "Europe/Vienna" },
  });
  fireEvent.click(screen.getByLabelText("Saturday, window 1"));
  fireEvent.change(screen.getByLabelText("Start time, window 1"), {
    target: { value: "22:00" },
  });
  fireEvent.change(screen.getByLabelText("End time, window 1"), {
    target: { value: "06:00" },
  });
  expect(screen.getByText(/Ends the following day/)).toBeInTheDocument();
  expect(configured().windows[0].days).toEqual([0, 1, 2, 3, 4, 5]);
  fireEvent.click(screen.getByRole("button", { name: "Add delivery window" }));
  expect(configured().windows).toHaveLength(2);
  fireEvent.click(screen.getByRole("button", { name: "Remove window 2" }));
  fireEvent.change(screen.getByLabelText("Send alerts"), {
    target: { value: "always" },
  });
  expect(configured()).toBeNull();
  fireEvent.change(screen.getByLabelText("Send alerts"), {
    target: { value: "scheduled" },
  });
  expect(configured().timezone).toBe("Europe/Vienna");
  expect(configured().windows[0].start).toBe("22:00");
});

test("invalid time zones, equal times and an empty weekday selection block form submission", () => {
  render(<Form />);
  fireEvent.change(screen.getByLabelText("Send alerts"), {
    target: { value: "scheduled" },
  });
  const timezone = screen.getByLabelText("Time zone") as HTMLInputElement;
  fireEvent.change(timezone, { target: { value: "No/Such_Zone" } });
  expect(timezone.checkValidity()).toBe(false);
  expect(screen.getByRole("alert")).toHaveTextContent("valid time zone");
  fireEvent.change(timezone, { target: { value: "europe/vienna" } });
  expect(timezone.checkValidity()).toBe(true);
  expect(configured().timezone).toBe("Europe/Vienna");
  fireEvent.change(timezone, { target: { value: "utc" } });
  expect(configured().timezone).toBe("UTC");
  const end = screen.getByLabelText("End time, window 1") as HTMLInputElement;
  fireEvent.change(end, { target: { value: "07:00" } });
  expect(end.checkValidity()).toBe(false);
  fireEvent.change(end, { target: { value: "17:00" } });
  expect(end.checkValidity()).toBe(true);
  for (const day of ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
    fireEvent.click(screen.getByLabelText(`${day}, window 1`));
  expect(
    (
      screen.getByLabelText("Monday, window 1") as HTMLInputElement
    ).checkValidity(),
  ).toBe(false);
  fireEvent.click(screen.getByLabelText("Sunday, window 1"));
  expect(
    (
      screen.getByLabelText("Monday, window 1") as HTMLInputElement
    ).checkValidity(),
  ).toBe(true);
});

test("summaries distinguish unrestricted, workday and overnight delivery", () => {
  expect(scheduleDescription()).toBe("Every day · 24 hours");
  expect(
    scheduleDescription({
      timezone: "Europe/Vienna",
      windows: [{ days: [4, 3, 2, 1, 0], start: "07:00", end: "17:00" }],
    }),
  ).toBe("Mon–Fri 07:00–17:00 · Europe/Vienna");
  expect(
    scheduleDescription({
      timezone: "UTC",
      windows: [{ days: [4], start: "22:00", end: "06:00" }],
    }),
  ).toContain("Fri 22:00–06:00 (+1 day)");
});
