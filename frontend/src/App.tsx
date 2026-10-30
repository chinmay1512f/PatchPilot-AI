import { useEffect, useState } from "react";
import { api, apiUrl } from "./api";
import type { Health } from "./types";
import { Icon } from "./ui";
import { Dashboard } from "./pages/Dashboard";
import { NewAnalysis } from "./pages/NewAnalysis";
import { JobView } from "./pages/JobView";

function useHashRoute() {
  const [hash, setHash] = useState(window.location.hash || "#/");
  useEffect(() => {
    const on = () => {
      setHash(window.location.hash || "#/");
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

function Logo() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M8 7l-5 5 5 5" /><path d="M16 7l5 5-5 5" /><path d="M10 13.5l1.6 1.6L14.5 10" />
    </svg>
  );
}

export function App() {
  const route = useHashRoute();
  const [health, setHealth] = useState<Health | null>(null);
  const [healthErr, setHealthErr] = useState(false);
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealthErr(true));
  }, []);

  const jobMatch = route.match(/^#\/jobs\/(job_[a-f0-9]+)/);
  const onNew = route.startsWith("#/new");
  let page = <Dashboard />;
  if (onNew) page = <NewAnalysis health={health} />;
  else if (jobMatch) page = <JobView id={jobMatch[1]} />;

  const claude = !health ? null : health.llm_mode === "replay"
    ? { tone: "violet", text: "API: replay" }
    : health.api_key_configured ? { tone: "ok", text: "API connected" } : { tone: "bad", text: "No API key" };
  const sandbox = !health ? null : health.execution.docker.available
    ? { tone: "ok", text: "Docker sandbox" } : { tone: "warn", text: "Local sandbox (consent)" };

  return (
    <div className="shell">
      <header className="topnav">
        <div className="topnav-inner">
          <a href="#/" className="brand">
            <span className="brand-mark"><Logo /></span>
            <span className="brand-name">Patch<span>Pilot</span> AI</span>
          </a>
          <nav className="navlinks">
            <a href="#/" className={!onNew && !jobMatch ? "active" : ""}><Icon name="grid" /><span className="label">Dashboard</span></a>
            <a href="#/new" className={onNew ? "active" : ""}><Icon name="plus" /><span className="label">New analysis</span></a>
          </nav>
          <div className="nav-status">
            {healthErr && <span className="nav-chip bad"><span className="dot" />Backend unreachable</span>}
            {claude && <span className={`nav-chip ${claude.tone}`}><span className="dot" />{claude.text}</span>}
            {sandbox && <span className={`nav-chip ${sandbox.tone}`} title={health?.execution.docker.detail}><span className="dot" />{sandbox.text}</span>}
            {health?.fast_mode && <span className="nav-chip violet" title="Claude fast mode: up to ~2.5x faster responses at 2x token price"><span className="dot" />⚡ Fast mode</span>}          </div>
        </div>
      </header>
      <main className="container">{page}</main>
      <footer className="footer">
        <div className="footer-inner">
          <span>Powered by <strong style={{ color: "var(--text-2)" }}>Claude</strong> · Anthropic API</span>
          <span className="spacer" />
          <span>Version 0.1 · AgentX Hackathon build</span>
          <span className="spacer" />
          <a href={apiUrl("/api/docs")} target="_blank" rel="noreferrer">API docs</a>
          <span>Original code is never modified</span>
        </div>
      </footer>
    </div>
  );
}
