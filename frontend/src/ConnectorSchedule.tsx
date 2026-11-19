import { useEffect, useId, useRef, useState } from "react";
import "./schedule.css";

export type DeliveryWindow = { days: number[]; start: string; end: string };
export type DeliverySchedule = { timezone: string; windows: DeliveryWindow[] };
const days = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];

function localTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}
function canonicalTimezone(value: string): string | null {
  if (!value.trim()) return null;
  try {
    const zone = new Intl.DateTimeFormat("en", {
      timeZone: value,
    }).resolvedOptions().timeZone;
    // Fixed numeric offsets accepted by recent Intl engines are not IANA ZoneInfo keys.
    return /^[+-]/.test(zone) ? null : zone;
  } catch {
    return null;
  }
}
const validTimezone = (value: string) => canonicalTimezone(value) !== null;
export function scheduleDescription(schedule?: DeliverySchedule | null) {
  if (!schedule) return "Every day · 24 hours";
  return (
    schedule.windows
      .map((window) => {
        const selected = [...window.days].sort((a, b) => a - b);
        const labels =
          selected.join() === "0,1,2,3,4"
            ? "Mon–Fri"
            : selected.length === 7
              ? "Every day"
              : selected.map((day) => days[day]?.slice(0, 3)).join(", ");
        return `${labels} ${window.start}–${window.end}${window.end < window.start ? " (+1 day)" : ""}`;
      })
      .join("; ") + ` · ${schedule.timezone}`
  );
}

function WindowFields({
  window,
  index,
  onChange,
  onRemove,
}: {
  window: DeliveryWindow;
  index: number;
  onChange: (value: DeliveryWindow) => void;
  onRemove?: () => void;
}) {
  const end = useRef<HTMLInputElement>(null);
  const id = useId();
  useEffect(() => {
    end.current?.setCustomValidity(
      window.start === window.end
        ? "Choose different start and end times. Use unrestricted delivery for 24 hours."
        : "",
    );
  }, [window.start, window.end]);
  return (
    <fieldset className="schedule-window">
      <legend>Window {index + 1}</legend>
      <div
        className="schedule-days"
        role="group"
        aria-label={`Days for window ${index + 1}`}
      >
        {days.map((day, number) => (
          <label className="schedule-day" key={day}>
            <input
              type="checkbox"
              checked={window.days.includes(number)}
              required={window.days.length === 0 && number === 0}
              aria-label={`${day}, window ${index + 1}`}
              onChange={(event) =>
                onChange({
                  ...window,
                  days: event.target.checked
                    ? [...window.days, number].sort((a, b) => a - b)
                    : window.days.filter((value) => value !== number),
                })
              }
            />
            <span>{day.slice(0, 3)}</span>
          </label>
        ))}
      </div>
      <div className="schedule-times">
        <label>
          From
          <input
            type="time"
            required
            value={window.start}
            aria-label={`Start time, window ${index + 1}`}
            onChange={(event) =>
              onChange({ ...window, start: event.target.value })
            }
          />
        </label>
        <label>
          Until
          <input
            ref={end}
            type="time"
            required
            value={window.end}
            aria-describedby={id}
            aria-label={`End time, window ${index + 1}`}
            onChange={(event) =>
              onChange({ ...window, end: event.target.value })
            }
          />
        </label>
        {onRemove && (
          <button
            type="button"
            className="text-button"
            aria-label={`Remove window ${index + 1}`}
            onClick={onRemove}
          >
            Remove window
          </button>
        )}
      </div>
      <p className="help" id={id}>
        {window.start === window.end
          ? "Choose different start and end times."
          : window.end < window.start
            ? "Ends the following day. Weekdays refer to the day this window starts."
            : "Delivery stops at the end time. Select at least one weekday."}
      </p>
    </fieldset>
  );
}

export default function ConnectorSchedule({
  value,
  onChange,
}: {
  value?: DeliverySchedule | null;
  onChange: (value: DeliverySchedule | null) => void;
}) {
  const [draft, setDraft] = useState<DeliverySchedule>(
    () =>
      value || {
        timezone: localTimezone(),
        windows: [{ days: [0, 1, 2, 3, 4], start: "07:00", end: "17:00" }],
      },
  );
  const timezone = useRef<HTMLInputElement>(null);
  const id = useId();
  const active = value ?? draft;
  useEffect(() => {
    if (value) setDraft(value);
  }, [value]);
  useEffect(() => {
    timezone.current?.setCustomValidity(
      validTimezone(active.timezone)
        ? ""
        : "Choose a valid IANA time zone, such as Europe/Vienna.",
    );
  }, [active.timezone, value]);
  const zones = (
    Intl as typeof Intl & { supportedValuesOf?: (key: string) => string[] }
  ).supportedValuesOf?.("timeZone") || [
    "Europe/Vienna",
    "Europe/Berlin",
    "Europe/London",
    "America/New_York",
    "Asia/Tokyo",
    "Australia/Sydney",
  ];
  function update(next: DeliverySchedule) {
    setDraft(next);
    onChange(next);
  }
  return (
    <fieldset className="connector-schedule">
      <legend>Delivery hours</legend>
      <p className="help">
        Choose when this destination can receive alerts. Monitoring continues
        around the clock.
      </p>
      <label>
        Send alerts
        <select
          value={value ? "scheduled" : "always"}
          onChange={(event) =>
            onChange(event.target.value === "always" ? null : draft)
          }
        >
          <option value="always">Any time · every day</option>
          <option value="scheduled">Only during selected hours</option>
        </select>
      </label>
      {value && (
        <>
          <label>
            Time zone
            <input
              ref={timezone}
              required
              list={`${id}-zones`}
              value={active.timezone}
              autoComplete="off"
              maxLength={100}
              aria-invalid={!validTimezone(active.timezone) || undefined}
              aria-describedby={`${id}-timezone-help`}
              onChange={(event) =>
                update({
                  ...active,
                  timezone:
                    canonicalTimezone(event.target.value) || event.target.value,
                })
              }
            />
          </label>
          <datalist id={`${id}-zones`}>
            <option value="UTC" />
            {zones.map((zone) => (
              <option key={zone} value={zone} />
            ))}
          </datalist>
          <p className="help" id={`${id}-timezone-help`}>
            Use an IANA time zone, for example Europe/Vienna. Times follow its
            daylight-saving changes.
          </p>
          {!validTimezone(active.timezone) && (
            <p className="schedule-error" role="alert">
              Choose a valid time zone from the suggestions.
            </p>
          )}
          <div className="schedule-presets">
            <span>Quick selection</span>
            <button
              type="button"
              className="secondary small"
              onClick={() =>
                update({
                  ...active,
                  windows: [
                    { days: [0, 1, 2, 3, 4], start: "07:00", end: "17:00" },
                  ],
                })
              }
            >
              Mon–Fri, 07–17
            </button>
            <button
              type="button"
              className="secondary small"
              onClick={() =>
                update({
                  ...active,
                  windows: [
                    {
                      days: [0, 1, 2, 3, 4, 5, 6],
                      start: "07:00",
                      end: "17:00",
                    },
                  ],
                })
              }
            >
              Every day, 07–17
            </button>
          </div>
          {active.windows.map((window, index) => (
            <WindowFields
              key={index}
              window={window}
              index={index}
              onChange={(next) =>
                update({
                  ...active,
                  windows: active.windows.map((old, number) =>
                    number === index ? next : old,
                  ),
                })
              }
              onRemove={
                active.windows.length > 1
                  ? () =>
                      update({
                        ...active,
                        windows: active.windows.filter(
                          (_, number) => number !== index,
                        ),
                      })
                  : undefined
              }
            />
          ))}
          {active.windows.length < 14 && (
            <button
              type="button"
              className="secondary small"
              onClick={() =>
                update({
                  ...active,
                  windows: [
                    ...active.windows,
                    { days: [0, 1, 2, 3, 4], start: "09:00", end: "12:00" },
                  ],
                })
              }
            >
              Add delivery window
            </button>
          )}
          <p className="schedule-preview" aria-live="polite">
            {scheduleDescription(active)}
          </p>
          <p className="help">
            Outside these hours, alerts stay queued until the next allowed
            window. Test messages follow these hours too. Provider rate limits
            still apply.
          </p>
        </>
      )}
    </fieldset>
  );
}
