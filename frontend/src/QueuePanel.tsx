import "./queue.css";

export type QueueSummary = {
  as_of: number;
  queued: number;
  ready: number;
  sending: number;
  last_sent_at: number | null;
  next_attempt_at: number | null;
  counts: Record<string, number>;
  destinations: {
    id: string;
    name: string;
    status: string;
    queued: number;
    sending: number;
    failed?: number;
    last_error?: string | null;
    min_interval_seconds: number | null;
    next_attempt_at: number | null;
    rate_limited_until: number | null;
  }[];
};
const date = (time: number) => new Date(time * 1000).toLocaleString();
export default function QueuePanel({
  summary,
  busy,
  onClear,
}: {
  summary?: QueueSummary;
  busy?: boolean;
  onClear?: () => void;
}) {
  if (!summary) return null;
  const labels: Record<string, string> = {
    sending: "Sending",
    ready: "Ready",
    rate_limited: "Telegram rate limit",
    pacing: "Configured send interval",
    retry_wait: "Retry backoff",
    disabled: "Disabled or unavailable",
    empty: "Queue empty",
    failed: "Failed deliveries",
  };
  return (
    <section className="delivery-queue" aria-label="Delivery queue">
      <div className="queue-heading">
        <h2>Delivery queue</h2>
        <span>
          {summary.queued.toLocaleString()} waiting · {summary.sending} in
          flight
        </span>
      </div>
      <p className="queue-summary">
        {summary.queued
          ? `${summary.ready.toLocaleString()} due; send intervals still apply. `
          : "No waiting messages. "}
        {summary.last_sent_at
          ? `Last successful delivery: ${date(summary.last_sent_at)}.`
          : "No successful delivery recorded yet."}
      </p>
      {summary.destinations
        .filter(
          (destination) =>
            destination.queued || destination.sending || destination.failed,
        )
        .map((destination) => (
          <div className="queue-destination" key={destination.id}>
            <strong>{destination.name}</strong>
            <span
              className={
                destination.status === "rate_limited" ? "queue-limited" : ""
              }
            >
              {labels[destination.status] || destination.status}
            </span>
            <small>
              {destination.queued.toLocaleString()} waiting
              {destination.failed
                ? ` · ${destination.failed.toLocaleString()} failed`
                : ""}
              {destination.min_interval_seconds !== null
                ? ` · minimum ${destination.min_interval_seconds}s between messages`
                : ""}
              {destination.rate_limited_until
                ? ` · Telegram cooldown until ${date(destination.rate_limited_until)}`
                : destination.next_attempt_at
                  ? ` · next eligible attempt: ${date(destination.next_attempt_at)}`
                  : ""}
            </small>
            {destination.last_error && (
              <small className="queue-last-error">
                Recorded delivery error: {destination.last_error}
              </small>
            )}
          </div>
        ))}
      <div className="queue-actions">
        <p>
          Clearing discards waiting messages and keeps their history. In-flight
          requests may finish.
        </p>
        <button
          className="secondary small"
          disabled={busy || !summary.queued || !onClear}
          onClick={onClear}
        >
          Clear waiting messages
        </button>
      </div>
    </section>
  );
}
