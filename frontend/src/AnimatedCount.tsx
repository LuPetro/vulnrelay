import { useEffect, useRef, useState } from "react";
import "./counter.css";

export function formatCount(value: number, locale?: string) {
  return value < 1000
    ? value.toLocaleString(locale)
    : `${(value / 1000).toLocaleString(locale, { maximumFractionDigits: 1 })}k`;
}

export default function AnimatedCount({
  value,
  motion,
}: {
  value: number;
  motion: boolean;
}) {
  const previous = useRef(value);
  const [from, setFrom] = useState<number | null>(null);
  useEffect(() => {
    const old = previous.current;
    previous.current = value;
    if (!motion || value <= old) {
      setFrom(null);
      return;
    }
    setFrom(old);
    const timer = setTimeout(() => setFrom(null), 700);
    return () => clearTimeout(timer);
  }, [value, motion]);
  return (
    <strong
      className={`animated-count ${from !== null ? "count-changed" : ""}`}
      title={value.toLocaleString()}
    >
      <span className="count-accessible">{value.toLocaleString()}</span>
      <span className="count-window" aria-hidden="true" key={value}>
        {from !== null && (
          <span className="count-previous">{formatCount(from)}</span>
        )}
        <span className="count-current">{formatCount(value)}</span>
      </span>
    </strong>
  );
}
