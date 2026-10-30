import { useState } from "react";

export interface Datum { key: string; label: string; value: number; color: string }

function niceMax(v: number) {
  if (v <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * pow >= v) return m * pow;
  return 10 * pow;
}

function SrTable({ data, caption }: { data: Datum[]; caption: string }) {
  return (
    <table className="sr-only">
      <caption>{caption}</caption>
      <tbody>{data.map((d) => <tr key={d.key}><th scope="row">{d.label}</th><td>{d.value}</td></tr>)}</tbody>
    </table>
  );
}

/** Vertical bar chart, single series (the title names it, so no legend). */
export function BarChart({ data, caption, unit = "findings" }: { data: Datum[]; caption: string; unit?: string }) {
  const [hot, setHot] = useState<number | null>(null);
  const W = 560, H = 250, L = 36, R = 8, T = 22, B = 34;
  const total = data.reduce((a, d) => a + d.value, 0);
  const max = niceMax(Math.max(1, ...data.map((d) => d.value)));
  const steps = [4, 5, 3, 2].find((n) => max % n === 0 && Number.isInteger(max / n)) ?? 4;
  const ticks = Array.from({ length: steps + 1 }, (_, i) => (max / steps) * i);
  const band = (W - L - R) / data.length;
  const bw = Math.min(64, band * 0.58);
  const y = (v: number) => T + (H - T - B) * (1 - v / max);
  const base = H - B;

  return (
    <div className="chart-wrap" onMouseLeave={() => setHot(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={caption}>
        {ticks.map((t) => (
          <g key={t}>
            <line className="chart-grid" x1={L} x2={W - R} y1={y(t)} y2={y(t)} />
            <text className="chart-axis" x={L - 8} y={y(t) + 4} textAnchor="end">{t}</text>
          </g>
        ))}
        <line className="chart-base" x1={L} x2={W - R} y1={base} y2={base} />
        {data.map((d, i) => {
          const cx = L + band * i + band / 2;
          const x = cx - bw / 2;
          const top = y(d.value);
          const h = base - top;
          const r = Math.min(4, h);
          const path = h > 0 ? `M${x},${base} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${base} Z` : "";
          return (
            <g key={d.key} onMouseEnter={() => setHot(i)}>
              {/* generous hit target */}
              <rect x={L + band * i} y={T} width={band} height={base - T} fill="transparent" />
              {path && <path className={`chart-bar ${hot === i ? "hot" : ""}`} d={path} fill={d.color} />}
              <text className="chart-value" x={cx} y={top - 7} textAnchor="middle">{d.value}</text>
              <text className="chart-axis" x={cx} y={H - 12} textAnchor="middle">{d.label}</text>
            </g>
          );
        })}
      </svg>
      {hot !== null && (
        <div className="chart-tip" style={{ left: `${((L + band * hot + band / 2) / W) * 100}%`, top: `${(y(data[hot].value) / H) * 100}%` }}>
          <strong>{data[hot].label}</strong>: {data[hot].value} {unit}{total ? ` · ${Math.round((data[hot].value / total) * 100)}%` : ""}
        </div>
      )}
      <SrTable data={data} caption={caption} />
    </div>
  );
}

/** Donut with center total, legend with values (labels carry identity, not color alone). */
export function DonutChart({ data, caption, centerLabel }: { data: Datum[]; caption: string; centerLabel: string }) {
  const [hot, setHot] = useState<string | null>(null);
  const total = data.reduce((a, d) => a + d.value, 0);
  const S = 200, C = S / 2, R = 86, r = 58;
  let angle = -Math.PI / 2;
  const arcs = data.filter((d) => d.value > 0).map((d) => {
    const sweep = (d.value / total) * Math.PI * 2;
    const a0 = angle, a1 = angle + sweep;
    angle = a1;
    const large = sweep > Math.PI ? 1 : 0;
    const p = (rad: number, a: number) => `${C + rad * Math.cos(a)},${C + rad * Math.sin(a)}`;
    const path = sweep >= Math.PI * 2 - 1e-6
      ? `M${C},${C - R} A${R},${R} 0 1 1 ${C - 0.01},${C - R} L${C - 0.01},${C - r} A${r},${r} 0 1 0 ${C},${C - r} Z`
      : `M${p(R, a0)} A${R},${R} 0 ${large} 1 ${p(R, a1)} L${p(r, a1)} A${r},${r} 0 ${large} 0 ${p(r, a0)} Z`;
    return { d, path };
  });
  const hotD = data.find((d) => d.key === hot);

  return (
    <div className="donut-layout">
      <div className="chart-wrap" style={{ width: 200 }} onMouseLeave={() => setHot(null)}>
        <svg viewBox={`0 0 ${S} ${S}`} role="img" aria-label={caption}>
          {total === 0 && <circle cx={C} cy={C} r={(R + r) / 2} fill="none" stroke="var(--surface-3)" strokeWidth={R - r} />}
          {arcs.map(({ d, path }) => (
            <path key={d.key} d={path} fill={d.color} stroke="#fff" strokeWidth={2} className={`chart-bar ${hot === d.key ? "hot" : ""}`} onMouseEnter={() => setHot(d.key)} />
          ))}
          <text className="donut-center-v" x={C} y={C + 4} textAnchor="middle">{hotD ? hotD.value : total}</text>
          <text className="donut-center-k" x={C} y={C + 22} textAnchor="middle">{hotD ? hotD.label : centerLabel}</text>
        </svg>
      </div>
      <div className="legend">
        {data.map((d) => (
          <div key={d.key} className={`legend-item ${hot === d.key ? "hot" : ""}`} onMouseEnter={() => setHot(d.key)} onMouseLeave={() => setHot(null)}>
            <span className="sw" style={{ background: d.color }} />
            <span>{d.label}</span>
            <span className="lv">{d.value}{total ? <span className="muted small" style={{ fontWeight: 500 }}> · {Math.round((d.value / total) * 100)}%</span> : null}</span>
          </div>
        ))}
      </div>
      <SrTable data={data} caption={caption} />
    </div>
  );
}
