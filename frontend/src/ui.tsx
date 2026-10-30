import { type ReactNode, useEffect, useState } from "react";
import { api } from "./api";

type Tone = "ok" | "warn" | "bad" | "info" | "violet" | "neutral" | "accent" | "outline";

const STATUS_TONE: Record<string, Tone> = {
  completed: "ok", verified: "ok", reproduced: "ok", fixed: "ok", appears_minimal: "ok",
  running: "accent", pending: "neutral", skipped: "neutral", not_run: "neutral", not_applicable: "neutral",
  failed: "bad", not_fixed: "bad", likely_excessive: "bad",
  blocked: "warn", inconclusive: "warn", incomplete: "warn", not_reproduced: "warn", unknown: "warn",
  possibly_broader_than_needed: "warn", insufficient_information: "neutral",
  unavailable: "neutral", timeout: "warn", no_tests: "neutral", error: "bad",
};

// Friendlier wording for a few status codes; everything else is shown as-is.
const FRIENDLY: Record<string, string> = {
  reproduced: "bug proven", not_reproduced: "bug not proven", fixed: "bug fixed", not_fixed: "not fixed yet",
  no_tests: "no tests found", unverified_location: "location not found",
};

export function label(s: string) {
  return FRIENDLY[s] ?? s.replace(/_/g, " ");
}

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return <span className={`badge ${tone}`} title={title}>{children}</span>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  if (!status) return <Badge>—</Badge>;
  const tone = STATUS_TONE[status] ?? "neutral";
  return (
    <Badge tone={tone}>
      <span className={`dot ${status === "running" ? "pulse" : ""}`} />
      {label(status)}
    </Badge>
  );
}

const SEV_TONE: Record<string, Tone> = { critical: "bad", high: "bad", medium: "warn", low: "info", info: "neutral" };
export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={SEV_TONE[severity] ?? "neutral"} title="Severity: impact if the issue is real">{severity === "critical" ? "● critical" : severity}</Badge>;
}
export function ConfidenceBadge({ confidence }: { confidence: string }) {
  return <Badge tone="outline" title="Confidence: how sure the analysis is (independent of severity)">confidence: {confidence}</Badge>;
}

/** Provenance label: tool evidence vs Claude-generated content. */
export function Src({ kind }: { kind: "tool" | "model" | "mixed" }) {
  const text = kind === "tool" ? "tool evidence" : kind === "model" ? "AI · Claude" : "tool + AI";
  const title = kind === "tool" ? "Produced by actual execution / scanning" : kind === "model" ? "Model-generated interpretation — not executed evidence" : "Deterministic evidence interpreted by Claude";
  return <span className={`src ${kind}`} title={title}>{text}</span>;
}

export function Empty({ title, children, icon = "search" }: { title: string; children?: ReactNode; icon?: IconName }) {
  return <div className="empty"><div className="empty-icon"><Icon name={icon} size={24} /></div><h3>{title}</h3>{children}</div>;
}

export function CodeView({ text, start = 1, highlight }: { text: string; start?: number; highlight?: [number, number] }) {
  const lines = text.replace(/\n$/, "").split("\n");
  return (
    <div className="code"><pre>
      {lines.map((l, i) => {
        const n = start + i;
        const hl = highlight && n >= highlight[0] && n <= highlight[1];
        return <div key={i} className={`ln ${hl ? "hl" : ""}`}><span className="n">{n}</span>{l || " "}</div>;
      })}
    </pre></div>
  );
}

/** Renders "  12| code" excerpts produced by the backend indexer. */
export function ExcerptView({ text, highlight }: { text: string; highlight?: [number, number] }) {
  const rows = text.split("\n").map((l) => {
    const m = l.match(/^\s*(\d+)\| ?(.*)$/);
    return m ? { n: Number(m[1]), code: m[2] } : { n: 0, code: l };
  });
  return (
    <div className="code"><pre>
      {rows.map((r, i) => (
        <div key={i} className={`ln ${highlight && r.n >= highlight[0] && r.n <= highlight[1] ? "hl" : ""}`}>
          <span className="n">{r.n || ""}</span>{r.code || " "}
        </div>
      ))}
    </pre></div>
  );
}

export function DiffView({ diff, maxHeight }: { diff: string; maxHeight?: number }) {
  if (!diff.trim()) return <div className="muted small">No changes.</div>;
  return (
    <div className="code" style={maxHeight ? { maxHeight } : undefined}><pre>
      {diff.replace(/\n$/, "").split("\n").map((l, i) => {
        const cls = l.startsWith("+++") || l.startsWith("---") ? "file" : l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "";
        return <div key={i} className={`ln ${cls}`}><span className="n" />{l || " "}</div>;
      })}
    </pre></div>
  );
}

export function FileModal({ jobId, path, version = "original", highlight, onClose }: { jobId: string; path: string; version?: string; highlight?: [number, number]; onClose: () => void }) {
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.file(jobId, path, version).then(setText).catch((e) => setErr(String(e.message ?? e)));
  }, [jobId, path, version]);
  useEffect(() => {
    if (text && highlight) document.getElementById("hl-anchor")?.scrollIntoView({ block: "center" });
  }, [text, highlight]);
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span className="mono">{path}</span>
          {highlight && <Badge tone="warn">lines {highlight[0]}–{highlight[1]}</Badge>}
          <Badge tone="outline">{version} · secrets redacted</Badge>
          <span className="spacer" />
          <button className="btn small" onClick={onClose}>Close</button>
        </div>
        <div className="modal-body">
          {err && <div className="alert bad">{err}</div>}
          {text === null && !err && <div className="muted">Loading…</div>}
          {text !== null && (
            <div className="code"><pre>
              {text.replace(/\n$/, "").split("\n").map((l, i) => {
                const n = i + 1;
                const hl = highlight && n >= highlight[0] && n <= highlight[1];
                return <div key={i} id={hl && n === highlight[0] ? "hl-anchor" : undefined} className={`ln ${hl ? "hl" : ""}`}><span className="n">{n}</span>{l || " "}</div>;
              })}
            </pre></div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------- minimal, XSS-safe markdown (renders React nodes, never raw HTML) ----------
function inline(text: string, key = 0): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|_[^_]+_)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let k = key;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith("`")) out.push(<code key={k++}>{t.slice(1, -1)}</code>);
    else if (t.startsWith("**")) out.push(<strong key={k++}>{t.slice(2, -2)}</strong>);
    else out.push(<em key={k++}>{t.slice(1, -1)}</em>);
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("```")) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) body.push(lines[i++]);
      i++;
      const lang = line.slice(3).trim();
      blocks.push(lang === "diff" ? <DiffView key={key++} diff={body.join("\n")} /> : <pre key={key++}><code>{body.join("\n")}</code></pre>);
      continue;
    }
    if (line.startsWith("|")) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        if (!/^\|[\s|:-]+\|$/.test(lines[i])) rows.push(lines[i].split("|").slice(1, -1).map((c) => c.trim()));
        i++;
      }
      blocks.push(
        <div className="table-wrap" key={key++}><table><thead><tr>{rows[0]?.map((c, j) => <th key={j}>{inline(c)}</th>)}</tr></thead>
          <tbody>{rows.slice(1).map((r, ri) => <tr key={ri}>{r.map((c, j) => <td key={j}>{inline(c)}</td>)}</tr>)}</tbody></table></div>,
      );
      continue;
    }
    if (/^\s*- /.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*- /.test(lines[i])) items.push(lines[i++].replace(/^\s*- /, ""));
      blocks.push(<ul key={key++}>{items.map((t, j) => <li key={j}>{inline(t)}</li>)}</ul>);
      continue;
    }
    const h = line.match(/^(#{1,3}) (.*)$/);
    if (h) {
      const Tag = (`h${h[1].length}`) as "h1" | "h2" | "h3";
      blocks.push(<Tag key={key++}>{inline(h[2])}</Tag>);
    } else if (line.startsWith("> ")) {
      blocks.push(<blockquote key={key++}>{inline(line.slice(2))}</blockquote>);
    } else if (line.trim() === "---") {
      blocks.push(<hr key={key++} />);
    } else if (line.trim()) {
      blocks.push(<p key={key++}>{inline(line)}</p>);
    }
    i++;
  }
  return <div className="md">{blocks}</div>;
}

export function fmtTime(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export const ANALYSIS_LABEL: Record<string, string> = {
  full_analysis: "Full analysis", full_repair: "Bug repair", investigate_only: "Investigation", security_scan: "Security scan", patch_review: "Patch review",
};

export type IconName =
  | "grid" | "plus" | "shield" | "bug" | "check" | "download" | "refresh" | "file" | "folder" | "chart" | "pie"
  | "search" | "beaker" | "wrench" | "alert" | "x" | "code" | "upload" | "lock" | "sparkle" | "dollar" | "list" | "git" | "cpu" | "eye" | "trash";

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  const p: Record<IconName, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
    plus: <path d="M12 5v14M5 12h14" />,
    shield: <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />,
    bug: <><rect x="8" y="7" width="8" height="12" rx="4" /><path d="M12 7V4M5 11h3M16 11h3M5 17h3M16 17h3" /></>,
    check: <path d="M5 12.5l4.5 4.5L19 7" />,
    download: <path d="M12 4v11M7 10l5 5 5-5M5 20h14" />,
    refresh: <path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7" />,
    file: <><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4M9 13h6M9 17h6" /></>,
    folder: <path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />,
    chart: <path d="M5 20V10M12 20V4M19 20v-7" />,
    pie: <><path d="M12 3a9 9 0 109 9h-9z" /><path d="M15 3.5A9 9 0 0120.5 9H15z" /></>,
    search: <><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></>,
    beaker: <path d="M9 3h6M10 3v6l-5 9a2 2 0 001.8 3h10.4a2 2 0 001.8-3l-5-9V3M7.5 15h9" />,
    wrench: <path d="M14.7 6.3a4 4 0 015 5L9 22l-3-3L16.7 8.3M14.7 6.3L12 3.6a4 4 0 00-5.3 5.3l2.6 2.7" />,
    alert: <><path d="M12 3l9.5 17h-19z" /><path d="M12 10v4M12 17.5v.01" /></>,
    x: <path d="M6 6l12 12M18 6L6 18" />,
    code: <path d="M9 7l-5 5 5 5M15 7l5 5-5 5" />,
    upload: <path d="M12 20V9M7 14l5-5 5 5M5 4h14" />,
    lock: <><rect x="5" y="10" width="14" height="10" rx="2" /><path d="M8 10V7a4 4 0 018 0v3" /></>,
    sparkle: <path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 17l.7 1.8 1.8.7-1.8.7L19 22l-.7-1.8-1.8-.7 1.8-.7z" />,
    dollar: <path d="M12 3v18M16.5 7.5C16 6 14.3 5 12 5s-4.5 1.2-4.5 3.2S9.5 11 12 11.5s4.5 1.3 4.5 3.3S14.5 19 12 19s-4.2-1-4.7-2.6" />,
    list: <path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01" />,
    git: <><circle cx="6" cy="6" r="2.2" /><circle cx="6" cy="18" r="2.2" /><circle cx="18" cy="9" r="2.2" /><path d="M6 8.2v7.6M18 11.2c0 3-4 3-8 5.6" /></>,
    cpu: <><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" /></>,
    eye: <><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z" /><circle cx="12" cy="12" r="3" /></>,
    trash: <><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13" /><path d="M10 11v6M14 11v6" /></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{p[name]}</svg>;
}
