# Connector delivery windows

Each Telegram connector can deliver continuously (the default) or only during chosen weekly windows. In **Connectors → Edit**, choose scheduled delivery, select an IANA timezone such as `Europe/Vienna`, and add one or more windows. For example, select Monday to Friday, `07:00`–`17:00`, to receive that destination's notifications during working hours.

Outside these windows, relevant alerts remain in the persistent queue. VulnRelay keeps synchronizing sources, matching assets and creating eligible alerts. When a window opens, delivery resumes using the normal pacing and retry rules. A schedule does not turn queued alerts into a digest or discard them. Before an alert is sent, the engine still checks the current rule, asset and CVE; obsolete alerts can be cancelled.

**Test notifications also respect the connector's windows.** To test outside a window, temporarily select continuous delivery or add a window covering the current time. A queued test is not proof of successful Telegram delivery; inspect its final delivery state.

## Time and weekday rules

- Each connector has its own timezone, independent of the server/browser timezone.
- The start time is inclusive and the end time is exclusive: `07:00`–`17:00` permits sends from exactly 07:00 until just before 17:00.
- A window whose end is earlier than its start continues into the following day. Friday `22:00`–`02:00` includes early Saturday, not early Friday.
- Multiple windows can be combined, including split working hours and overlapping windows. A maximum of 14 windows is supported.
- Equal start/end times, empty weekday selections and empty enabled schedules are rejected. Choose continuous delivery for 24/7 service.

Schedules follow local wall-clock time through daylight saving changes. During a spring-forward gap, nonexistent times do not occur: a partly skipped window opens at the first existing local time inside it, and a wholly skipped window waits until its next weekly occurrence. During fall-back, both occurrences of an eligible local time are allowed. A message already sent remains deduplicated; the repeated hour does not create a second copy of it.

Python's standard-library `zoneinfo` uses the host's installed IANA timezone database. Native installations need system timezone data (for example the Debian/Ubuntu `tzdata` package). A missing or unknown timezone is rejected rather than silently falling back to UTC. Keep the host/container timezone data current when timezone laws change.

## Queue diagnostics and delivery guarantees

The Overview and Connectors queue panels show **outside schedule**, the configured timezone, and the next eligible attempt. The CLI reports the same data:

```bash
docker compose exec monitor vulnrelay queue status
```

Without Docker, use `vulnrelay queue status`.

The next attempt combines the message's retry deadline, connector pacing, any Telegram cooldown, and the delivery windows. A Telegram cooldown that ends after Friday's window closes can defer delivery until Monday morning. The engine does not bypass Telegram limits to fit a window. A large backlog can take several windows to drain.

Waiting outside a window does not claim messages, increment delivery attempts/failures or reserve connector pacing. Schedules are stored with the connector and survive restarts. Changing a window or returning to continuous delivery takes effect on subsequent worker checks without rewriting the waiting messages' timestamps. The worker checks configuration and the window again after alert revalidation, before starting an outbound request.

An HTTP request already in flight may complete after a window closes or the connector is edited. Delivery remains at least once; an uncertain response followed by a retry can still produce a duplicate at the provider. Windows do not provide exactly-once guarantees. Separate VulnRelay installations do not share delivery limits.

Use **Clear waiting messages** only to discard an unwanted backlog deliberately. Dismissed history and deduplication keys remain, and in-flight messages are not recalled. See [Delivery queue](delivery-queue.md).

## Portable configuration and API fields

Connector configuration remains ordinary JSON stored in the existing document table; this feature needs no database migration. Omitting `delivery_schedule`, or setting it to `null`, preserves continuous delivery for existing installations.

```json
{
  "name": "Office security alerts",
  "kind": "telegram",
  "enabled": true,
  "token_env": "TELEGRAM_BOT_TOKEN",
  "chat_id": "-1001234567890",
  "min_interval_seconds": 3.1,
  "delivery_schedule": {
    "timezone": "Europe/Vienna",
    "windows": [
      {
        "days": [0, 1, 2, 3, 4],
        "start": "07:00",
        "end": "17:00"
      }
    ]
  }
}
```

Weekdays are numbered Monday `0` through Sunday `6`. Times use zero-padded `HH:MM` values. The existing create/update endpoints are `POST /api/config/connectors` and `PUT /api/config/connectors/{id}` with the normal authentication and mutation protections.

`GET /api/queue/status` and `GET /api/overview` expose the queue summary. Each destination additionally includes:

- `status: "outside_schedule"` when waiting outside its window (an active Telegram cooldown takes precedence as the status).
- `schedule_timezone`: configured IANA timezone, or `null` for continuous delivery.
- `schedule_resume_at`: the next window opening when currently outside the schedule, as a Unix timestamp; otherwise `null`.
- `next_attempt_at`: the first eligible attempt after combining the schedule with retry/pacing/provider deadlines; `null` for a disabled, empty or already sending destination.

Invalid legacy connector schedules fail closed and become inspectable configuration failures instead of silently sending outside the requested window. Disabled or removed connectors retain the existing failure inspection behavior.
