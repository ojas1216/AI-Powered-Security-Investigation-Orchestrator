import { useEffect, useState } from "react";
import { askCopilot, ingestSampleAlert, listInvestigations } from "./api";
import type { InvestigationPackage } from "./types";

const sevColor: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
};

function VerdictBadge({ v }: { v: string }) {
  const color =
    v === "malicious" ? "bg-critical" : v === "suspicious" ? "bg-high" : "bg-slate-600";
  // Note: text content only — never dangerouslySetInnerHTML (XSS-safe).
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold ${color}`}>{v}</span>;
}

export function App() {
  const [items, setItems] = useState<InvestigationPackage[]>([]);
  const [selected, setSelected] = useState<InvestigationPackage | null>(null);
  const [answer, setAnswer] = useState("");
  const [error, setError] = useState("");

  async function refresh() {
    try {
      setItems(await listInvestigations());
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function runSample() {
    setError("");
    try {
      const pkg = await ingestSampleAlert();
      setSelected(pkg);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function ask(q: string) {
    if (!selected) return;
    const res = await askCopilot(selected.investigation_id, q);
    setAnswer(res.answer);
  }

  return (
    <div className="min-h-screen p-6 max-w-6xl mx-auto">
      <header className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">🛡️ AegisFlow — Investigation Console</h1>
        <button
          onClick={runSample}
          className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded font-medium"
        >
          Run sample phishing investigation
        </button>
      </header>

      {error && <p className="text-critical mb-4">Error: {error}</p>}

      <div className="grid grid-cols-3 gap-6">
        <aside className="col-span-1 space-y-2">
          <h2 className="text-sm uppercase text-slate-400">Investigations</h2>
          {items.map((i) => (
            <button
              key={i.investigation_id}
              onClick={() => setSelected(i)}
              className="w-full text-left bg-slate-900 hover:bg-slate-800 p-3 rounded"
            >
              <div className="flex justify-between items-center">
                <span className="truncate">{i.investigation_id.slice(0, 8)}</span>
                <VerdictBadge v={i.overall_verdict} />
              </div>
              {i.risk && (
                <span
                  className={`mt-1 inline-block px-2 py-0.5 rounded text-xs ${
                    sevColor[i.risk.severity] ?? "bg-slate-600"
                  }`}
                >
                  risk {i.risk.score}
                </span>
              )}
            </button>
          ))}
          {items.length === 0 && <p className="text-slate-500 text-sm">No investigations yet.</p>}
        </aside>

        <main className="col-span-2">
          {selected ? (
            <Detail pkg={selected} onAsk={ask} answer={answer} />
          ) : (
            <p className="text-slate-500">Select or run an investigation.</p>
          )}
        </main>
      </div>
    </div>
  );
}

function Detail({
  pkg,
  onAsk,
  answer,
}: {
  pkg: InvestigationPackage;
  onAsk: (q: string) => void;
  answer: string;
}) {
  return (
    <div className="space-y-4">
      <div className="bg-slate-900 p-4 rounded">
        <div className="flex justify-between">
          <h3 className="font-semibold">Verdict & Risk</h3>
          <VerdictBadge v={pkg.overall_verdict} />
        </div>
        {pkg.risk && (
          <>
            <p className="text-3xl font-bold mt-2">
              {pkg.risk.score}{" "}
              <span className="text-base text-slate-400">/ 100 ({pkg.risk.severity})</span>
            </p>
            <ul className="text-sm text-slate-400 list-disc ml-5 mt-2">
              {pkg.risk.rationale.map((r, idx) => (
                <li key={idx}>{r}</li>
              ))}
            </ul>
          </>
        )}
      </div>

      <Section title="Executive summary">
        <p className="text-slate-300 whitespace-pre-wrap">{pkg.executive_summary}</p>
      </Section>

      <Section title={`IOCs (${pkg.iocs.length})`}>
        <table className="w-full text-sm">
          <tbody>
            {pkg.iocs.map((e, idx) => (
              <tr key={idx} className="border-b border-slate-800">
                <td className="py-1 text-slate-400">{e.ioc.type}</td>
                <td className="py-1 font-mono">{e.ioc.value}</td>
                <td className="py-1 text-right">
                  <VerdictBadge v={e.verdict} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="MITRE ATT&CK">
        <div className="flex flex-wrap gap-2">
          {pkg.mitre.map((t) => (
            <span key={t.technique_id} className="bg-slate-800 px-2 py-1 rounded text-xs">
              {t.technique_id} {t.name}
            </span>
          ))}
        </div>
      </Section>

      <Section title="Timeline">
        <ul className="text-sm space-y-1">
          {pkg.timeline.map((ev, idx) => (
            <li key={idx} className="text-slate-300">
              <span className="text-slate-500">{ev.timestamp.slice(11, 19)}</span>{" "}
              {ev.action} {ev.detail ? `— ${ev.detail}` : ""}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Affected">
        <p className="text-sm">Hosts: {pkg.affected_hosts.join(", ") || "none"}</p>
        <p className="text-sm">Users: {pkg.affected_users.join(", ") || "none"}</p>
      </Section>

      <Section title="Copilot">
        <div className="flex gap-2 flex-wrap">
          {["Why is this malicious?", "Show affected hosts", "What ATT&CK techniques?"].map(
            (q) => (
              <button
                key={q}
                onClick={() => onAsk(q)}
                className="bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded text-sm"
              >
                {q}
              </button>
            )
          )}
        </div>
        {answer && <p className="mt-3 text-slate-300 whitespace-pre-wrap">{answer}</p>}
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-slate-900 p-4 rounded">
      <h3 className="font-semibold mb-2">{title}</h3>
      {children}
    </div>
  );
}
