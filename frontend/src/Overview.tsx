import { useEffect, useState } from "react";
import { ArrowRight, Check, ChevronRight, Pause, Play } from "lucide-react";
import AnimatedCount from "./AnimatedCount";
import QueuePanel, { type QueueSummary } from "./QueuePanel";
import "./overview.css";

export type OverviewData = {
  counts: Record<string, number>;
  sources: {
    source: string;
    last_success_at?: string | number;
    last_error?: string;
    next_attempt_at?: number;
    last_attempt_at?: number;
    retry_scheduled?: boolean;
  }[];
  deliveries: Record<string, number>;
  engine: Record<string, number>;
  setup_required: boolean;
  opencve_enabled?: boolean;
  osv_enabled?: boolean;
  queue?: QueueSummary;
};
type Item = {
  id: string;
  name: string;
  enabled: boolean;
  group?: string;
  environment?: string;
};
type Delivery = {
  id: string;
  connector_id: string;
  state: string;
  created_at: number;
  attempts: number;
  last_error?: string;
};
type Props = {
  overview: OverviewData;
  assets: Item[];
  rules: Item[];
  connectors: Item[];
  deliveries: Delivery[];
  navigate: (page: string) => void;
  clearQueue?: () => void;
  busy?: boolean;
};
const date = (value?: string | number) =>
  value
    ? new Date(
        typeof value === "number" ? value * 1000 : value,
      ).toLocaleString()
    : "Never synchronized";
const sourceNames = [
  { id: "nvd", label: "NVD", detail: "CVE records & severity" },
  { id: "cisa_kev", label: "CISA KEV", detail: "Known exploitation" },
  { id: "epss", label: "FIRST EPSS", detail: "Exploitation probability" },
  { id: "opencve", label: "OpenCVE", detail: "Additional assessments" },
  { id: "osv", label: "OSV", detail: "Package version advisories" },
];

function PacketLayer({ paths }: { paths: string[] }) {
  return (
    <g className="relay-packets">
      {paths.map((d, i) => (
        <circle
          key={d}
          r="3"
          className={`signal-flow signal-packet packet-${i} ${i < 3 ? "packet-input" : ""}`}
          style={{ offsetPath: `path("${d}")` }}
        />
      ))}
    </g>
  );
}

function FlowIllustration({
  rules,
  destinations,
}: {
  rules: number;
  destinations: number;
}) {
  const paths = [
    "M149 51H202Q224 51 224 73V115Q224 137 246 137",
    "M149 113H198Q216 113 226 124Q238 137 246 137",
    "M149 175H198Q216 175 226 158Q238 137 246 137",
    "M149 242H255Q275 242 275 222V190Q275 169 295 169",
    "M395 137H486",
    "M584 137H651",
    "M246 137H295",
  ];
  const mobilePaths = [
    "M58 58V76Q58 94 76 94H152Q170 94 170 112",
    "M170 58V112",
    "M282 58V76Q282 94 264 94H188Q170 94 170 112",
    "M95 163H132",
    "M170 202V243",
    "M208 265H244",
    "M170 112V126",
  ];
  return (
    <div className="signal-map" aria-hidden="true">
      <svg className="relay-desktop" viewBox="0 0 760 288" fill="none">
        <path className="relay-guide" d="M16 19H744M16 269H744" />
        {[19, 269].map((y) => (
          <g key={y} className="relay-registration">
            <path d={`M16 ${y - 4}V${y + 4}M744 ${y - 4}V${y + 4}`} />
          </g>
        ))}
        {paths.map((d) => (
          <path key={d} d={d} className="relay-track" />
        ))}
        {[
          { y: 51, title: "NVD", detail: "CVE records" },
          { y: 113, title: "CISA KEV", detail: "Known exploitation" },
          { y: 175, title: "FIRST EPSS", detail: "Exploit probability" },
        ].map((source, i) => (
          <g key={source.title} className={`relay-input relay-input-${i}`}>
            <rect x="16" y={source.y - 20} width="133" height="41" rx="2" />
            <circle cx="30" cy={source.y} r="2.5" />
            <text x="42" y={source.y - 1} className="relay-node-title">
              {source.title}
            </text>
            <text x="42" y={source.y + 12} className="relay-node-detail">
              {source.detail}
            </text>
          </g>
        ))}
        <g className="relay-inventory">
          <rect x="16" y="225" width="133" height="34" rx="2" />
          <text x="29" y="247" className="relay-node-title">
            Your assets
          </text>
        </g>
        <g className="relay-core">
          <rect x="295" y="87" width="100" height="100" rx="3" />
          <path
            className="relay-core-corner"
            d="M287 99V79H307M383 79H403V99M403 175V195H383M307 195H287V175"
          />
          <image
            href="/brand/vulnrelay-mark.svg"
            x="313"
            y="99"
            width="64"
            height="64"
          />
          <path className="relay-core-scan" d="M314 174H376" pathLength="100" />
        </g>
        <text x="345" y="63" textAnchor="middle" className="relay-stage-label">
          01 / MATCH
        </text>
        <g className="relay-filter">
          <rect x="486" y="103" width="98" height="68" rx="2" />
          {[0, 1, 2].map((i) => (
            <g key={i}>
              <path
                className="relay-filter-baseline"
                d={`M504 ${121 + i * 15}H566`}
              />
              <path
                className={`relay-rule-scan relay-rule-${i}`}
                d={`M504 ${121 + i * 15}H${548 - i * 9}`}
              />
            </g>
          ))}
        </g>
        <text x="535" y="79" textAnchor="middle" className="relay-stage-label">
          02 / FILTER
        </text>
        <text x="535" y="195" textAnchor="middle" className="relay-node-title">
          {rules} active {rules === 1 ? "rule" : "rules"}
        </text>
        <g className="relay-output">
          <rect x="651" y="103" width="77" height="68" rx="2" />
          <g className="relay-output-sheet">
            <rect x="664" y="116" width="51" height="42" rx="1" />
            <path d="M674 126h23M674 134h31M674 142h16" />
          </g>
        </g>
        <text x="689" y="79" textAnchor="middle" className="relay-stage-label">
          03 / NOTIFY
        </text>
        <text x="689" y="195" textAnchor="middle" className="relay-node-title">
          {destinations} {destinations === 1 ? "destination" : "destinations"}
        </text>
        <text x="345" y="222" textAnchor="middle" className="relay-node-title">
          VulnRelay
        </text>
        <PacketLayer paths={paths} />
      </svg>
      <svg className="relay-mobile" viewBox="0 0 340 342" fill="none">
        {mobilePaths.map((d) => (
          <path key={d} d={d} className="relay-track" />
        ))}
        {[
          { x: 14, title: "NVD" },
          { x: 126, title: "CISA KEV" },
          { x: 238, title: "FIRST EPSS" },
        ].map((source, i) => (
          <g key={source.title} className={`relay-input relay-input-${i}`}>
            <rect x={source.x} y="18" width="88" height="40" rx="2" />
            <text
              x={source.x + 44}
              y="43"
              textAnchor="middle"
              className="relay-node-title"
            >
              {source.title}
            </text>
          </g>
        ))}
        <text x="14" y="8" className="relay-stage-label">
          PUBLIC INTELLIGENCE
        </text>
        <g className="relay-inventory">
          <rect x="10" y="145" width="85" height="36" rx="2" />
          <text x="19" y="167" className="relay-node-title">
            Your assets
          </text>
        </g>
        <g className="relay-core">
          <rect x="132" y="126" width="76" height="76" rx="3" />
          <path
            className="relay-core-corner"
            d="M125 137V119H143M197 119H215V137M215 191V209H197M143 209H125V191"
          />
          <image
            href="/brand/vulnrelay-mark.svg"
            x="147"
            y="136"
            width="46"
            height="46"
          />
          <path className="relay-core-scan" d="M146 191H194" pathLength="100" />
        </g>
        <text x="235" y="159" className="relay-node-title">
          VulnRelay
        </text>
        <text x="235" y="175" className="relay-stage-label">
          01 / MATCH
        </text>
        <g className="relay-filter">
          <rect x="132" y="243" width="76" height="44" rx="2" />
          {[0, 1, 2].map((i) => (
            <g key={i}>
              <path
                className="relay-filter-baseline"
                d={`M145 ${255 + i * 10}H194`}
              />
              <path
                className={`relay-rule-scan relay-rule-${i}`}
                d={`M145 ${255 + i * 10}H${183 - i * 7}`}
              />
            </g>
          ))}
        </g>
        <g className="relay-output">
          <rect x="244" y="243" width="76" height="44" rx="2" />
          <g className="relay-output-sheet">
            <rect x="258" y="252" width="48" height="26" rx="1" />
            <path d="M266 260h24M266 268h16" />
          </g>
        </g>
        <text x="170" y="312" textAnchor="middle" className="relay-stage-label">
          02 / FILTER
        </text>
        <text x="282" y="312" textAnchor="middle" className="relay-stage-label">
          03 / NOTIFY
        </text>
        <text x="170" y="330" textAnchor="middle" className="relay-node-title">
          {rules} active {rules === 1 ? "rule" : "rules"}
        </text>
        <text x="282" y="330" textAnchor="middle" className="relay-node-title">
          {destinations} {destinations === 1 ? "destination" : "destinations"}
        </text>
        <PacketLayer paths={mobilePaths} />
      </svg>
    </div>
  );
}

export default function OverviewPage({
  overview,
  assets,
  rules,
  connectors,
  deliveries,
  navigate,
  clearQueue,
  busy,
}: Props) {
  const [paused, setPaused] = useState(
    () => localStorage.getItem("vulnrelay-motion") === "paused",
  );
  const [reduced, setReduced] = useState(false);
  const [hidden, setHidden] = useState(document.hidden);
  useEffect(() => {
    const preference = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    const change = () => setReduced(preference?.matches ?? false);
    const visibility = () => setHidden(document.hidden);
    change();
    preference?.addEventListener("change", change);
    document.addEventListener("visibilitychange", visibility);
    return () => {
      preference?.removeEventListener("change", change);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, []);
  const heartbeat =
    overview.engine.delivery_heartbeat || overview.engine.last_cycle;
  const recent = Boolean(heartbeat && Date.now() / 1000 - heartbeat < 120);
  const activeAssets = assets.filter((a) => a.enabled).length;
  const activeRules = rules.filter((r) => r.enabled).length;
  const activeConnectors = connectors.filter((c) => c.enabled).length;
  const queued =
    (overview.deliveries.pending || 0) + (overview.deliveries.retry || 0);
  const failed = overview.deliveries.failed || 0;
  const sourceErrors = overview.sources.filter((s) => s.last_error).length;
  const groups = [...new Set(assets.map((a) => a.group || "Ungrouped"))];
  const needsAttention =
    failed > 0 || sourceErrors > 0 || Boolean(heartbeat && !recent);
  const setupSteps = [
    {
      label: "Add your assets",
      text: "Choose technologies you actually run.",
      done: assets.length > 0,
      target: "Assets",
    },
    {
      label: "Connect a destination",
      text: "Give your alerts a destination.",
      done: connectors.length > 0,
      target: "Connectors",
    },
    {
      label: "Create a rule",
      text: "Decide what deserves your attention.",
      done: rules.length > 0,
      target: "Notification rules",
    },
  ];
  const kpis = [
    {
      label: "Enabled assets",
      value: activeAssets,
      note: `${assets.length} total · ${groups.length} groups`,
      target: "Assets",
    },
    {
      label: "Active rules",
      value: activeRules,
      note: "Your notification conditions",
      target: "Notification rules",
    },
    {
      label: "Enabled connectors",
      value: activeConnectors,
      note: "Notification destinations",
      target: "Connectors",
    },
    {
      label: "Sent messages",
      value: overview.deliveries.sent || 0,
      note: `${queued} queued · includes test messages`,
      target: "Connectors",
    },
  ];
  return (
    <div
      className="overview-page"
      data-motion={paused || reduced || hidden ? "paused" : "running"}
    >
      <section
        className={`overview-status ${needsAttention ? "attention" : recent ? "recent" : "waiting"}`}
        aria-label="Engine status"
      >
        <span className="overview-status-marker" aria-hidden="true">
          <span />
        </span>
        <div className="overview-status-copy">
          <strong>
            {needsAttention
              ? "Attention required"
              : recent
                ? "Monitoring worker connected"
                : "Waiting for the monitoring worker"}
          </strong>
          <p>
            {heartbeat
              ? `Last heartbeat: ${date(heartbeat)}`
              : "Configure your assets, rules and destination, then start the worker."}
          </p>
        </div>
        <span className="overview-status-pill">
          {recent
            ? "Recent heartbeat"
            : heartbeat
              ? "Stale heartbeat"
              : "Waiting for monitor"}
        </span>
      </section>
      {needsAttention && (
        <div className="overview-attention" role="status">
          {sourceErrors > 0 && (
            <button onClick={() => navigate("Settings")}>
              {sourceErrors} source error(s) <ChevronRight size={14} />
            </button>
          )}
          {failed > 0 && (
            <button onClick={() => navigate("Connectors")}>
              {failed} failed message(s) <ChevronRight size={14} />
            </button>
          )}
          {heartbeat && !recent && (
            <span>Check the worker before relying on fresh alerts.</span>
          )}
        </div>
      )}

      <section className="overview-route" aria-label="Your intelligence relay">
        <div className="overview-route-brief">
          <span className="overview-eyebrow">THE SIGNAL PATH</span>
          <h2>
            Intelligence in.
            <br />
            Relevance out.
          </h2>
          <p>
            Assets set the scope.
            <br />
            Rules decide what gets through.
          </p>
          <button
            className="overview-link"
            onClick={() => navigate("Notification rules")}
          >
            Review your rules <ArrowRight size={15} />
          </button>
          <span className="overview-route-footnote">
            Local-first. Notification-first.
          </span>
        </div>
        <div className="overview-route-diagram">
          <FlowIllustration
            rules={activeRules}
            destinations={activeConnectors}
          />
          <div className="overview-flow-caption">
            <span>How alerts flow · illustrative animation</span>
            <button
              disabled={reduced}
              aria-label={
                reduced
                  ? "Motion reduced by system preference"
                  : paused
                    ? "Resume overview animation"
                    : "Pause overview animation"
              }
              onClick={() => {
                localStorage.setItem(
                  "vulnrelay-motion",
                  paused ? "running" : "paused",
                );
                setPaused(!paused);
              }}
            >
              {paused ? <Play size={12} /> : <Pause size={12} />}
              {reduced
                ? "Reduced motion"
                : paused
                  ? "Resume motion"
                  : "Pause motion"}
            </button>
          </div>
        </div>
      </section>

      <section className="overview-coverage" aria-label="Monitoring coverage">
        <div className="overview-section-heading overview-coverage-heading">
          <h2>
            <span className="overview-section-index">01</span> Your coverage
          </h2>
          <button className="overview-link" onClick={() => navigate("Catalog")}>
            Explore the catalog <ArrowRight size={15} />
          </button>
        </div>
        <div className="overview-kpis">
          {kpis.map(({ label, value, note, target }, i) => (
            <button
              className={`overview-kpi overview-enter-${i}`}
              key={label}
              onClick={() => navigate(target)}
            >
              <span className="overview-kpi-label">{label}</span>
              {label === "Sent messages" ? (
                <AnimatedCount
                  value={value}
                  motion={!paused && !reduced && !hidden}
                />
              ) : (
                <strong>{value.toLocaleString()}</strong>
              )}
              <span className="overview-kpi-note">
                {note}
                <ArrowRight size={14} />
              </span>
            </button>
          ))}
        </div>
      </section>

      <QueuePanel summary={overview.queue} busy={busy} onClear={clearQueue} />

      {overview.setup_required && (
        <section className="overview-setup" aria-label="First-run setup">
          <div className="overview-section-heading">
            <h2>A few steps to your first alert</h2>
            <span className="overview-meta">
              {setupSteps.filter((s) => s.done).length} / 3 configured
            </span>
          </div>
          <div className="overview-setup-steps">
            {setupSteps.map((step, i) => (
              <button key={step.label} onClick={() => navigate(step.target)}>
                <span
                  className={`overview-step-number ${step.done ? "done" : ""}`}
                >
                  {step.done ? <Check size={16} /> : `0${i + 1}`}
                </span>
                <strong>{step.label}</strong>
                <p>{step.text}</p>
                <ArrowRight size={16} />
              </button>
            ))}
          </div>
        </section>
      )}

      <div className="overview-registers">
        <section
          className="overview-register"
          aria-label="Intelligence sources"
        >
          <div className="overview-section-heading">
            <h2>
              <span className="overview-section-index">02</span> Intelligence
              sources
            </h2>
            <span className="overview-meta">
              {sourceNames.length} providers
            </span>
          </div>
          <ul className="overview-source-list">
            {sourceNames.map(({ id, label, detail }, i) => {
              const source = overview.sources.find((s) => s.source === id);
              const manual =
                (id === "opencve" && !overview.opencve_enabled) ||
                (id === "osv" && !overview.osv_enabled);
              const state = source?.last_error
                ? source.retry_scheduled
                  ? "retrying"
                  : "error"
                : manual
                  ? "manual"
                  : source?.last_success_at
                    ? "synced"
                    : "pending";
              return (
                <li className="overview-source" key={id}>
                  <span className="overview-row-index" aria-hidden="true">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <div className="overview-source-body">
                    <strong>
                      {label}
                      <span>{detail}</span>
                    </strong>
                    {source?.last_error && (
                      <small>Last sync failed: {source.last_error}</small>
                    )}
                    <small>
                      {source?.last_success_at
                        ? `Last success: ${date(source.last_success_at)}`
                        : manual
                          ? "Optional · lookup on demand"
                          : "Waiting for the first successful sync"}
                    </small>
                    {!manual && source?.next_attempt_at && (
                      <small>
                        {source.retry_scheduled
                          ? "Retry scheduled"
                          : "Next sync"}
                        {": "}
                        {date(source.next_attempt_at)}
                      </small>
                    )}
                  </div>
                  <span className={`overview-source-state ${state}`}>
                    <span aria-hidden="true" />
                    {state === "retrying"
                      ? "Retry scheduled"
                      : state === "error"
                        ? "Last sync failed"
                        : state === "manual"
                          ? "Manual"
                          : state === "synced"
                            ? "Synced"
                            : "Not synced"}
                  </span>
                </li>
              );
            })}
          </ul>
          <div className="overview-source-footer">
            <span>
              <strong>
                {(overview.counts.vulnerabilities || 0).toLocaleString()}
              </strong>{" "}
              local CVE records
            </span>
            <button
              className="overview-link"
              onClick={() => navigate("Vulnerabilities")}
            >
              Browse records <ArrowRight size={14} />
            </button>
          </div>
          <p className="overview-metric-note">
            CVSS / severity · EPSS / probability · KEV / known exploitation
          </p>
        </section>
        <section className="overview-register" aria-label="Recent deliveries">
          <div className="overview-section-heading">
            <h2>
              <span className="overview-section-index">03</span> Recent
              deliveries
            </h2>
            <button
              className="overview-link"
              onClick={() => navigate("Connectors")}
            >
              View history <ArrowRight size={14} />
            </button>
          </div>
          {deliveries.length === 0 ? (
            <div className="overview-quiet">
              <span className="overview-quiet-dash" aria-hidden="true">
                —
              </span>
              <h3>No deliveries yet.</h3>
              <p>
                When a CVE matches your rules, its delivery will appear here.
              </p>
              <button
                className="overview-link"
                onClick={() => navigate("Notification rules")}
              >
                Review your rules <ArrowRight size={14} />
              </button>
            </div>
          ) : (
            <ol className="overview-delivery-list">
              {deliveries.slice(0, 5).map((row) => (
                <li key={row.id}>
                  <span
                    className={`overview-delivery-marker ${row.state === "sent" ? "sent" : row.state === "failed" ? "error" : row.state === "dismissed" || row.state === "cancelled" ? "muted" : ""}`}
                    aria-hidden="true"
                  />
                  <div className="overview-delivery-body">
                    <strong>
                      {connectors.find((c) => c.id === row.connector_id)
                        ?.name || "Removed destination"}
                    </strong>
                    <small>
                      {date(row.created_at)} · {row.attempts} attempt(s)
                    </small>
                    <span className="overview-delivery-id">
                      {row.id.slice(0, 8)}
                      {row.last_error ? ` · ${row.last_error}` : ""}
                    </span>
                  </div>
                  <span
                    className={`overview-source-state ${row.state === "sent" ? "synced" : row.state === "failed" ? "error" : "pending"}`}
                  >
                    {row.state}
                  </span>
                </li>
              ))}
            </ol>
          )}
          <div className="overview-delivery-footer">
            <span>{queued} waiting in queue</span>
            <span className={failed ? "overview-failed" : ""}>
              {failed} failed
            </span>
          </div>
        </section>
      </div>

      <section className="overview-groups" aria-label="Asset groups">
        <div className="overview-section-heading">
          <h2>
            <span className="overview-section-index">04</span> Environments
            under watch
          </h2>
          <button className="overview-link" onClick={() => navigate("Assets")}>
            Manage assets <ArrowRight size={14} />
          </button>
        </div>
        {groups.length === 0 ? (
          <div className="overview-group-empty">
            <div>
              <strong>Start with the things you run.</strong>
              <p>Select technologies or assemble an environment pack.</p>
            </div>
            <button
              className="overview-link"
              onClick={() => navigate("Catalog")}
            >
              Find your stack <ArrowRight size={15} />
            </button>
          </div>
        ) : (
          <div className="overview-group-list">
            {groups.map((group, i) => {
              const members = assets.filter(
                (a) => (a.group || "Ungrouped") === group,
              );
              const enabled = members.filter((a) => a.enabled).length;
              const environments = [
                ...new Set(members.map((a) => a.environment).filter(Boolean)),
              ];
              return (
                <button
                  className="overview-group"
                  key={group}
                  onClick={() => navigate("Assets")}
                >
                  <span className="overview-row-index">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="overview-group-name">
                    <strong>{group}</strong>
                    <span>
                      {members.length}{" "}
                      {members.length === 1 ? "asset" : "assets"}
                    </span>
                  </span>
                  <span className="overview-group-products">
                    {members
                      .slice(0, 4)
                      .map((a) => a.name)
                      .join(" · ")}
                    {members.length > 4 ? ` · +${members.length - 4} more` : ""}
                  </span>
                  <span className="overview-group-meta">
                    {enabled} enabled
                    {environments.length ? (
                      <small>{environments.join(", ")}</small>
                    ) : null}
                  </span>
                  <ArrowRight size={16} />
                </button>
              );
            })}
          </div>
        )}
      </section>
      <div className="overview-bottom-note">
        <span>VULNRELAY / INSTANCE OVERVIEW</span>
        <span>Intelligence has a destination.</span>
      </div>
    </div>
  );
}
