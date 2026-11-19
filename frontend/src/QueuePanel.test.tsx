import { afterEach, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import QueuePanel from "./QueuePanel";

afterEach(cleanup);
test("scheduled queue renders an explicit next attempt even for native-only timezone aliases", () => {
  render(
    <QueuePanel
      summary={{
        as_of: 1800000000,
        queued: 1,
        ready: 0,
        sending: 0,
        last_sent_at: null,
        next_attempt_at: 1800010000,
        counts: { pending: 1 },
        destinations: [
          {
            id: "scheduled",
            name: "Night shift",
            status: "outside_schedule",
            queued: 1,
            sending: 0,
            min_interval_seconds: 3.1,
            next_attempt_at: 1800010000,
            rate_limited_until: null,
            schedule_timezone: "posix/Europe/Vienna",
            schedule_resume_at: 1800010000,
          },
        ],
      }}
    />,
  );
  expect(screen.getByText("Outside delivery hours")).toBeInTheDocument();
  expect(screen.getByText(/next eligible attempt:.*UTC/)).toBeInTheDocument();
  expect(
    screen.getByText(/delivery time zone: posix\/Europe\/Vienna/),
  ).toBeInTheDocument();
});
