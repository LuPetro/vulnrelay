import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDownLeft,
  ArrowRight,
  Check,
  ChevronRight,
  CircleAlert,
  Database,
  Layers3,
  ListFilter,
  Pause,
  Play,
  Radio,
  Send,
  Sparkles,
} from "lucide-react";
import "./overview.css";

export type OverviewData = {
  counts: Record<string, number>;
  sources: {
    source: string;
    last_success_at?: string | number;
    last_error?: string;
  }[];
  deliveries: Record<string, number>;
  engine: Record<string, number>;
  setup_required: boolean;
  opencve_enabled?: boolean;
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
};
const date = (value?: string | number) =>
  value
    ? new Date(
        typeof value === "number" ? value * 1000 : value,
      ).toLocaleString()
    : "Never synchronized";
const sourceNames = [
  { id: "nvd", label: "NVD", detail: "CVE records & severity", letter: "N" },
  {
    id: "cisa_kev",
    label: "CISA KEV",
    detail: "Known exploitation",
    letter: "C",
  },
  {
    id: "epss",
    label: "FIRST EPSS",
    detail: "Exploitation probability",
    letter: "E",
  },
  {
    id: "opencve",
    label: "OpenCVE",
    detail: "Additional assessments",
    letter: "O",
  },
];

function FlowIllustration() {
  const paths = [
    "M105 64H167Q193 64 193 100V145Q193 169 223 169H267",
    "M105 169H267",
    "M105 274H167Q193 274 193 245V196Q193 169 223 169",
    "M337 169H407Q431 169 431 145V104H502",
    "M534 138V217",
  ];
  return (
    <div className="signal-map" aria-hidden="true">
      <svg viewBox="0 0 610 338" fill="none">
        <defs>
          <radialGradient id="relay-glow">
            <stop stopColor="#4777f5" stopOpacity=".24" />
            <stop offset="1" stopColor="#4777f5" stopOpacity="0" />
          </radialGradient>
          <pattern
            id="relay-grid"
            width="24"
            height="24"
            patternUnits="userSpaceOnUse"
          >
            <circle cx="1" cy="1" r="1" fill="#7394ce" opacity=".22" />
          </pattern>
        </defs>
        <rect width="610" height="338" fill="url(#relay-grid)" />
        <circle cx="302" cy="169" r="155" fill="url(#relay-glow)" />
        <circle
          className="signal-halo"
          cx="302"
          cy="169"
          r="70"
          stroke="#7295d2"
          strokeOpacity=".2"
        />
        <circle
          cx="302"
          cy="169"
          r="114"
          stroke="#7295d2"
          strokeOpacity=".13"
          strokeDasharray="3 7"
        />
        {paths.map((d, i) => (
          <g key={d}>
            <path d={d} stroke="#385782" strokeWidth="1.5" />
            <path
              className={`signal-flow signal-flow-${i}`}
              d={d}
              stroke={i > 2 ? "#74e0bb" : "#84a8ff"}
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeDasharray="4 58"
            />
          </g>
        ))}
        {[
          { y: 43, label: "CVE records", mark: "N" },
          { y: 148, label: "Exploitation", mark: "K" },
          { y: 253, label: "Your assets", mark: "A" },
        ].map((n) => (
          <g key={n.label}>
            <rect
              x="16"
              y={n.y}
              width="123"
              height="42"
              rx="10"
              fill="#192e50"
              stroke="#3a5279"
            />
            <text
              x="31"
              y={n.y + 26}
              fill="#91b4ff"
              fontSize="12"
              fontWeight="700"
            >
              {n.mark}
            </text>
            <text x="53" y={n.y + 26} fill="#dce7fa" fontSize="11">
              {n.label}
            </text>
          </g>
        ))}
        <g className="signal-hub">
          <rect
            x="256"
            y="123"
            width="92"
            height="92"
            rx="24"
            fill="#132a4d"
            stroke="#6185c6"
          />
          <image
            href="/brand/vulnrelay-mark.svg"
            x="270"
            y="136"
            width="64"
            height="64"
          />
        </g>
        {[
          { y: 83, label: "Your rules", detail: "Match & filter" },
          { y: 217, label: "Your channel", detail: "Relevant alerts" },
        ].map((n) => (
          <g key={n.label}>
            <rect
              x="474"
              y={n.y}
              width="120"
              height="55"
              rx="12"
              fill="#183b3d"
              stroke="#456d68"
            />
            <text
              x="490"
              y={n.y + 23}
              fill="#a6f2d7"
              fontSize="12"
              fontWeight="650"
            >
              {n.label}
            </text>
            <text x="490" y={n.y + 40} fill="#c1dcd9" fontSize="10">
              {n.detail}
            </text>
          </g>
        ))}
        <text
          x="302"
          y="242"
          textAnchor="middle"
          fill="#dce7fa"
          fontSize="12"
          fontWeight="650"
        >
          VulnRelay
        </text>
        <text x="302" y="262" textAnchor="middle" fill="#9bb4d9" fontSize="10">
          Your intelligence relay
        </text>
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
      label: "Connect Telegram",
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
      icon: Layers3,
      target: "Assets",
    },
    {
      label: "Active rules",
      value: activeRules,
      note: "Your notification conditions",
      icon: ListFilter,
      target: "Notification rules",
    },
    {
      label: "Enabled connectors",
      value: activeConnectors,
      note: "Configured Telegram destinations",
      icon: Radio,
      target: "Connectors",
    },
    {
      label: "Sent messages",
      value: overview.deliveries.sent || 0,
      note: `${queued} queued · includes test messages`,
      icon: Send,
      target: "Connectors",
    },
  ];
  return (
    <div
      className="overview-page"
      data-motion={paused || reduced || hidden ? "paused" : "running"}
    >
      <section className="overview-hero" aria-label="Your intelligence relay">
        <div className="overview-hero-copy">
          <div className="overview-eyebrow">
            <span className="overview-dot" /> YOUR PERSONAL INTELLIGENCE RELAY
          </div>
          <h2>
            Your stack.
            <br />
            <span>Connected.</span>
          </h2>
          <p>
            From vulnerability intelligence to the alerts that matter to you.
            One quiet place to keep it all moving.
          </p>
          <button
            className="overview-hero-cta"
            onClick={() => navigate("Catalog")}
          >
            Explore the catalog <ArrowRight size={17} />
          </button>
          <div className="overview-hero-note">
            <Check size={13} /> Self-hosted <span /> Local-first
          </div>
        </div>
        <div className="overview-flow">
          <FlowIllustration />
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

      <section
        className={`overview-status ${needsAttention ? "attention" : recent ? "recent" : "waiting"}`}
        aria-label="Engine status"
      >
        <span className="overview-status-icon">
          {needsAttention ? <CircleAlert size={20} /> : <Activity size={20} />}
        </span>
        <div>
          <strong>
            {needsAttention
              ? "A few things need attention"
              : recent
                ? "Monitoring heartbeat received"
                : "Ready for your first signal"}
          </strong>
          <p>
            {heartbeat
              ? `Last worker heartbeat: ${date(heartbeat)}`
              : "Start the monitoring worker after configuring your assets, rules and destination."}
          </p>
        </div>
        <span className="overview-status-pill">
          <span />
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
            <span>
              Check the monitoring worker before relying on fresh alerts.
            </span>
          )}
        </div>
      )}

      <div className="overview-kpis">
        {kpis.map(({ label, value, note, icon: Icon, target }, i) => (
          <button
            className={`overview-kpi overview-enter-${i}`}
            key={label}
            onClick={() => navigate(target)}
          >
            <span className="overview-kpi-label">
              {label}
              <Icon size={17} />
            </span>
            <strong>{value.toLocaleString()}</strong>
            <span className="overview-kpi-note">
              {note}
              <ArrowRight size={14} />
            </span>
          </button>
        ))}
      </div>

      {overview.setup_required && (
        <section className="overview-setup" aria-label="First-run setup">
          <div className="overview-section-title">
            <div>
              <span className="overview-eyebrow">MAKE IT YOURS</span>
              <h2>A few steps to your first alert</h2>
            </div>
            <span className="overview-setup-count">
              {setupSteps.filter((s) => s.done).length} / 3 configured
            </span>
          </div>
          <div className="overview-setup-steps">
            {setupSteps.map((s, i) => (
              <button key={s.label} onClick={() => navigate(s.target)}>
                <span
                  className={`overview-step-number ${s.done ? "done" : ""}`}
                >
                  {s.done ? <Check size={16} /> : `0${i + 1}`}
                </span>
                <div>
                  <strong>{s.label}</strong>
                  <p>{s.text}</p>
                </div>
                <ArrowRight size={16} />
              </button>
            ))}
          </div>
        </section>
      )}

      <div className="overview-columns">
        <section className="overview-panel" aria-label="Intelligence sources">
          <div className="overview-section-title">
            <div>
              <span className="overview-eyebrow">THE INPUT</span>
              <h2>Intelligence sources</h2>
            </div>
            <Database size={19} />
          </div>
          <div className="overview-source-list">
            {sourceNames.map(({ id, label, detail, letter }) => {
              const source = overview.sources.find((s) => s.source === id);
              const manual = id === "opencve" && !overview.opencve_enabled;
              const state = source?.last_error
                ? "error"
                : manual
                  ? "manual"
                  : source?.last_success_at
                    ? "synced"
                    : "pending";
              return (
                <div className="overview-source" key={id}>
                  <span className={`overview-source-mark source-${id}`}>
                    {letter}
                  </span>
                  <div className="overview-source-body">
                    <strong>
                      {label}
                      <span>{detail}</span>
                    </strong>
                    <small>
                      {source?.last_error ||
                        (source?.last_success_at
                          ? `Last success: ${date(source.last_success_at)}`
                          : manual
                            ? "Optional · lookup on demand"
                            : "Waiting for the first successful sync")}
                    </small>
                  </div>
                  <span className={`overview-source-state ${state}`}>
                    {state === "error"
                      ? "Error"
                      : state === "manual"
                        ? "Manual"
                        : state === "synced"
                          ? "Synced"
                          : "Not synced"}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="overview-source-footer">
            <span>
              <strong>
                {(overview.counts.vulnerabilities || 0).toLocaleString()}
              </strong>{" "}
              local CVE records
            </span>
            <button onClick={() => navigate("Vulnerabilities")}>
              Browse intelligence <ArrowRight size={14} />
            </button>
          </div>
          <p className="overview-metric-note">
            CVSS: severity · EPSS: exploitation probability · KEV: known
            exploitation
          </p>
        </section>
        <section className="overview-panel" aria-label="Recent deliveries">
          <div className="overview-section-title">
            <div>
              <span className="overview-eyebrow">THE OUTPUT</span>
              <h2>Recent deliveries</h2>
            </div>
            <button
              className="text-button"
              onClick={() => navigate("Connectors")}
            >
              View history <ArrowRight size={14} />
            </button>
          </div>
          {deliveries.length === 0 ? (
            <div className="overview-quiet">
              <div className="overview-quiet-icon">
                <Send size={27} />
                <span />
                <span />
              </div>
              <h3>Your channel is quiet</h3>
              <p>
                When a CVE matches your rules, its delivery will appear here.
              </p>
              <button
                className="text-button"
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
                    className={`overview-delivery-icon ${row.state === "sent" ? "sent" : ""}`}
                  >
                    {row.state === "sent" ? (
                      <Check size={15} />
                    ) : (
                      <ArrowDownLeft size={15} />
                    )}
                  </span>
                  <div>
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
            <span>{failed} failed</span>
          </div>
        </section>
      </div>

      <section
        className="overview-panel overview-groups"
        aria-label="Asset groups"
      >
        <div className="overview-section-title">
          <div>
            <span className="overview-eyebrow">YOUR WATCHLIST</span>
            <h2>Every environment. In view.</h2>
          </div>
          <button className="text-button" onClick={() => navigate("Assets")}>
            Manage assets <ArrowRight size={14} />
          </button>
        </div>
        {groups.length === 0 ? (
          <div className="overview-group-empty">
            <Layers3 size={25} />
            <div>
              <strong>Start with the things you run.</strong>
              <p>
                Select individual technologies or assemble an environment pack.
              </p>
            </div>
            <button className="secondary" onClick={() => navigate("Catalog")}>
              Find your stack <ArrowRight size={15} />
            </button>
          </div>
        ) : (
          <div className="overview-group-grid">
            {groups.map((group, i) => {
              const members = assets.filter(
                (a) => (a.group || "Ungrouped") === group,
              );
              const enabled = members.filter((a) => a.enabled).length;
              return (
                <button
                  className={`overview-group group-accent-${i % 3}`}
                  key={group}
                  onClick={() => navigate("Assets")}
                >
                  <span className="overview-group-top">
                    <span className="overview-group-symbol">
                      <Layers3 size={21} />
                    </span>
                    <span>{members.length} assets</span>
                    <ArrowRight size={15} />
                  </span>
                  <strong>{group}</strong>
                  <p>
                    {members
                      .slice(0, 4)
                      .map((a) => a.name)
                      .join(" · ")}
                    {members.length > 4 ? ` · +${members.length - 4} more` : ""}
                  </p>
                  <span className="overview-group-meta">
                    {enabled} enabled
                    {[
                      ...new Set(
                        members.map((a) => a.environment).filter(Boolean),
                      ),
                    ].length
                      ? ` · ${[...new Set(members.map((a) => a.environment).filter(Boolean))].join(", ")}`
                      : ""}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </section>
      <div className="overview-bottom-note">
        <Sparkles size={14} /> Built around your stack. Delivered on your terms.
      </div>
    </div>
  );
}
