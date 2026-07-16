/**
 * IOC Threat-Intelligence Dossier — the enterprise enrichment view. One
 * indicator produces a complete dossier: overview, per-provider threat intel,
 * DNS, WHOIS, hosting, MITRE, campaign correlation, relationships, timeline,
 * business impact, evidence and references. Backed by POST /intel/dossier.
 */
import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ChevronDown, ChevronRight, Download, Loader2, Search } from "lucide-react";
import { getDossier } from "@/services/platform";
import { useAudit } from "@/hooks/useAudit";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState } from "@/components/common/states";
import { VerdictBadge } from "@/components/common/badges";
import { CopyButton } from "@/components/common/CopyButton";
import { ActorBadge } from "@/components/investigation/ActorBadge";
import { DossierGraph } from "@/components/investigation/DossierGraph";
import type { ThreatIntelligenceDossier } from "@/types/api";

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const tone = pct >= 75 ? "bg-critical" : pct >= 40 ? "bg-high" : "bg-info";
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="h-1.5 w-20 overflow-hidden rounded-full bg-[#172033]">
        <span className={`block h-full ${tone}`} style={{ width: `${pct}%` }} />
      </span>
      <span className="text-xs text-fg-subtle">{pct}%</span>
    </span>
  );
}

export function IocReportPage() {
  const [params, setParams] = useSearchParams();
  const audit = useAudit();
  const [text, setText] = useState("");
  const [d, setD] = useState<ThreatIntelligenceDossier | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [ran, setRan] = useState("");

  const run = useCallback(
    async (value: string) => {
      const q = value.trim();
      if (!q) return;
      setBusy(true);
      setError("");
      setRan(q);
      try {
        const res = await getDossier(q);
        setD(res);
        audit("ioc.dossier", res.indicator);
      } catch {
        setError("Could not build the dossier. Is the API reachable?");
        setD(null);
      } finally {
        setBusy(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  useEffect(() => {
    const q = params.get("q");
    if (q) {
      setText(q);
      void run(q);
      setParams({}, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function exportJson() {
    if (!d) return;
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dossier-${d.indicator}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <PageHeader
        title="IOC Dossier"
        description="Complete threat-intelligence report for any IP, domain, URL, hash, email, ASN or CIDR."
      />

      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run(text);
        }}
        className="mb-5 flex gap-2"
      >
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" />
          <Input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="malware-c2.net · 45.155.205.99 · <sha256> · AS13335 · 10.0.0.0/24"
            className="pl-9"
            autoFocus
          />
        </div>
        <Button type="submit" disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Investigate"}
        </Button>
        {d && (
          <Button variant="secondary" onClick={exportJson} type="button">
            <Download className="mr-1 h-4 w-4" /> Export
          </Button>
        )}
      </form>

      {error && <ErrorState message={error} onRetry={() => run(ran)} />}
      {!error && !d && !busy && (
        <EmptyState
          title="Investigate an indicator"
          description="Paste an IOC above, or use the global search (press ⌘K / Ctrl+K)."
        />
      )}
      {busy && !d && (
        <div className="flex items-center gap-2 p-8 text-sm text-fg-subtle">
          <Loader2 className="h-4 w-4 animate-spin" /> Building dossier for {ran}…
        </div>
      )}

      {d && <Dossier d={d} />}
    </div>
  );
}

function Dossier({ d }: { d: ThreatIntelligenceDossier }) {
  const [filter, setFilter] = useState("");
  const providers = d.threat_intel.filter((p) =>
    !filter ||
    `${p.source} ${p.malware_family} ${p.threat_category} ${p.detail}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  );
  return (
    <div className="space-y-4">
      {/* Overview */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="break-all font-mono text-lg text-fg">{d.indicator}</span>
            <CopyButton value={d.indicator} />
            <Badge tone="neutral">{d.ioc_type}</Badge>
            <VerdictBadge verdict={d.verdict} />
            <Badge tone="neutral">{d.status}</Badge>
            {d.attribution && d.attribution.actor_type !== "unattributed" && (
              <ActorBadge attribution={d.attribution} />
            )}
          </div>
          <p className="mt-2 text-sm text-fg-subtle">{d.executive_summary}</p>
          <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-fg-subtle">
            <span>
              risk <span className="font-semibold text-fg">{d.risk_score}/100</span>
            </span>
            <span className="inline-flex items-center gap-1.5">
              confidence <ConfidenceBar value={d.confidence.score} />
            </span>
            {d.classification && <span>classification {d.classification}</span>}
          </div>
          {d.confidence.rationale.length > 0 && (
            <p className="mt-1 text-xs text-fg-subtle">
              {d.confidence.rationale.join(" ")}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Threat intelligence */}
      <Section title={`Threat Intelligence (${d.threat_intel.length} sources)`}>
        <div className="mb-2">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter sources / malware / category…"
            className="max-w-xs"
          />
        </div>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
              <tr>
                <th className="px-3 py-2 font-medium">Source</th>
                <th className="px-3 py-2 font-medium">Verdict</th>
                <th className="px-3 py-2 font-medium">Confidence</th>
                <th className="px-3 py-2 font-medium">Malware</th>
                <th className="px-3 py-2 font-medium">Category</th>
                <th className="px-3 py-2 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {providers.map((p, i) => (
                <tr key={`${p.source}:${i}`}>
                  <td className="px-3 py-2 font-medium text-fg">{p.source}</td>
                  <td className="px-3 py-2"><VerdictBadge verdict={p.verdict} /></td>
                  <td className="px-3 py-2"><ConfidenceBar value={p.confidence} /></td>
                  <td className="px-3 py-2 text-fg-subtle">{p.malware_family || "—"}</td>
                  <td className="px-3 py-2 text-fg-subtle">{p.threat_category || "—"}</td>
                  <td className="px-3 py-2 text-fg-subtle">{p.detail || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {hasRel(d) && (
        <Section title="Relationship Graph">
          <DossierGraph indicator={d.indicator} rel={d.relationships} />
        </Section>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {d.whois && (
          <Section title="WHOIS">
            <KV k="Registrar" v={d.whois.registrar} />
            <KV k="Created" v={fmt(d.whois.created)} />
            <KV k="Expires" v={fmt(d.whois.expires)} />
            <KV k="Age" v={d.whois.age_days != null ? `${d.whois.age_days} days` : "—"} />
            <KV k="TLD" v={d.whois.tld} />
            <KV k="DNSSEC" v={d.whois.dnssec ? "enabled" : "disabled"} />
            <KV k="Nameservers" v={d.whois.nameservers.join(", ")} />
          </Section>
        )}
        {d.dns && (
          <Section title="DNS Records">
            {(["a", "aaaa", "mx", "txt", "ns", "cname"] as const).map((r) =>
              d.dns![r].length ? (
                <KV key={r} k={r.toUpperCase()} v={d.dns![r].join(", ")} />
              ) : null,
            )}
          </Section>
        )}
        {d.hosting && (
          <Section title="Hosting">
            <KV k="ASN" v={d.hosting.asn} />
            <KV k="ISP" v={d.hosting.isp} />
            <KV k="Organization" v={d.hosting.organization} />
            <KV k="Country" v={d.hosting.country} />
            {d.hosting.cloud_provider && <KV k="Cloud" v={d.hosting.cloud_provider} />}
          </Section>
        )}
        {d.mitre.techniques.length > 0 && (
          <Section title="MITRE ATT&CK">
            <div className="flex flex-wrap gap-1.5">
              {d.mitre.techniques.map((t) => (
                <Badge key={t.technique_id} tone="medium">
                  {t.technique_id} · {t.name}
                </Badge>
              ))}
            </div>
            {d.mitre.predicted_next.length > 0 && (
              <p className="mt-2 text-xs text-fg-subtle">
                Predicted next: {d.mitre.predicted_next.join(" → ")}
              </p>
            )}
          </Section>
        )}
      </div>

      {(hasRel(d) || d.campaign_matches.length > 0) && (
        <Section title="Relationships & Campaign Correlation">
          <RelList label="Related IPs" items={d.relationships.related_ips} />
          <RelList label="Related domains" items={d.relationships.related_domains} />
          <RelList label="Related hashes" items={d.relationships.related_hashes} />
          <RelList label="Threat actors / malware" items={d.relationships.threat_actors} />
          {d.campaign_matches.length > 0 && (
            <div className="mt-2 text-xs text-fg-subtle">
              Correlates with {d.campaign_matches.length} prior incident(s):{" "}
              {d.campaign_matches.map((m) => m.title || m.investigation_id).join(", ")}
            </div>
          )}
        </Section>
      )}

      {(d.timeline.first_seen || d.timeline.events.length > 0) && (
        <Section title="Timeline">
          <KV k="First seen" v={fmt(d.timeline.first_seen)} />
          <KV k="Last seen" v={fmt(d.timeline.last_seen)} />
          {d.timeline.events.map((e, i) => (
            <p key={i} className="text-xs text-fg-subtle">• {e}</p>
          ))}
        </Section>
      )}

      {d.business_impact && (
        <Section title="Business Impact & Recommendations">
          <KV k="Technical" v={d.business_impact.technical_impact} />
          <KV k="Business" v={d.business_impact.business_impact} />
          <KV k="Data exposure" v={d.business_impact.potential_data_exposure} />
          <ul className="mt-2 space-y-1">
            {d.business_impact.recommended_actions.map((a, i) => (
              <li key={i} className="text-sm text-fg-subtle">→ {a}</li>
            ))}
          </ul>
        </Section>
      )}

      {(d.evidence.length > 0 || d.references.length > 0) && (
        <Section title="Evidence & References">
          {d.evidence.map((e, i) => (
            <p key={i} className="font-mono text-xs text-fg-subtle">{e}</p>
          ))}
          {d.references.map((r, i) => (
            <a key={i} href={r} target="_blank" rel="noreferrer"
               className="block truncate text-xs text-info hover:underline">
              {r}
            </a>
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(true);
  return (
    <Card>
      <CardHeader className="pb-2">
        <button
          onClick={() => setOpen((v) => !v)}
          className="flex w-full items-center gap-1.5 text-left"
        >
          {open ? (
            <ChevronDown className="h-4 w-4 text-fg-subtle" />
          ) : (
            <ChevronRight className="h-4 w-4 text-fg-subtle" />
          )}
          <CardTitle className="text-sm">{title}</CardTitle>
        </button>
      </CardHeader>
      {open && <CardContent className="space-y-1.5 pt-0">{children}</CardContent>}
    </Card>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  if (!v) return null;
  return (
    <div className="flex gap-2 text-sm">
      <span className="w-32 shrink-0 text-xs uppercase text-fg-subtle">{k}</span>
      <span className="break-all text-fg">{v}</span>
    </div>
  );
}

function RelList({ label, items }: { label: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-sm">
      <span className="text-xs uppercase text-fg-subtle">{label}:</span>
      {items.map((it) => (
        <span key={it} className="rounded bg-[#172033] px-1.5 py-0.5 font-mono text-xs text-fg-subtle">
          {it}
        </span>
      ))}
    </div>
  );
}

function hasRel(d: ThreatIntelligenceDossier) {
  const r = d.relationships;
  return (
    r.related_ips.length + r.related_domains.length + r.related_hashes.length +
      r.threat_actors.length >
    0
  );
}

function fmt(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}
