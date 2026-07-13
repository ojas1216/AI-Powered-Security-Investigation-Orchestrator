/**
 * Full IOC report — the destination for a global-search lookup of a domain,
 * IP, hash, URL or email. Unlike the small Threat-Intel table, this assembles a
 * complete picture per indicator: fused verdict + confidence, every source's
 * individual verdict/score/detail, threat actors, sightings, on-host EDR
 * sightings, and related past investigations from long-term memory. One pivot,
 * one report.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  Crosshair,
  History,
  Loader2,
  Search,
  ShieldAlert,
} from "lucide-react";
import { runHunt, type HuntResult } from "@/services/hunts";
import { useAudit } from "@/hooks/useAudit";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState } from "@/components/common/states";
import { VerdictBadge } from "@/components/common/badges";
import { CopyButton } from "@/components/common/CopyButton";
import { RelatedCases } from "@/components/investigation/RelatedCases";
import type { EnrichedIOC, Verdict } from "@/types/api";

const VERDICT_RANK: Record<Verdict, number> = {
  malicious: 0,
  suspicious: 1,
  unknown: 2,
  benign: 3,
};

export function IocReportPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const audit = useAudit();
  const [text, setText] = useState("");
  const [result, setResult] = useState<HuntResult | null>(null);
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
        const r = await runHunt({ text: q });
        setResult(r);
        audit("ioc.report", `${r.iocs.length} indicators`);
      } catch (err: unknown) {
        const status = (err as { response?: { status?: number } })?.response?.status;
        setError(
          status === 422
            ? "No valid indicator (IP, domain, URL, hash, or email) found in that input."
            : "Lookup failed. Is the API reachable?",
        );
        setResult(null);
      } finally {
        setBusy(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  // Deep-link from global search: /ioc-report?q=<indicator> prefills + auto-runs.
  useEffect(() => {
    const q = params.get("q");
    if (q) {
      setText(q);
      void run(q);
      setParams({}, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const worst = useMemo<Verdict | null>(() => {
    if (!result?.iocs.length) return null;
    return result.iocs
      .map((e) => e.verdict)
      .sort((a, b) => VERDICT_RANK[a] - VERDICT_RANK[b])[0];
  }, [result]);

  return (
    <div>
      <PageHeader
        title="IOC Report"
        description="Look up any IP, domain, URL, file hash, or email for a complete cross-source report."
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
            placeholder="8.8.8.8 · evil.com · hxxps://bad[.]link · <sha256> · user@corp.com"
            className="pl-9"
            autoFocus
          />
        </div>
        <Button type="submit" disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Look up"}
        </Button>
      </form>

      {error && <ErrorState message={error} onRetry={() => run(ran)} />}

      {!error && !result && !busy && (
        <EmptyState
          icon={<Crosshair className="h-8 w-8" />}
          title="Search an indicator"
          description="Paste an IOC above, or use the global search (press / anywhere)."
        />
      )}

      {busy && !result && (
        <div className="flex items-center gap-2 p-8 text-sm text-fg-subtle">
          <Loader2 className="h-4 w-4 animate-spin" /> Correlating {ran} across
          threat intel, EDR, and case memory…
        </div>
      )}

      {result && (
        <div className="space-y-4">
          {/* Verdict banner */}
          <Card>
            <CardContent className="flex flex-wrap items-center justify-between gap-3 pt-4">
              <div className="flex items-center gap-3">
                <ShieldAlert
                  className={
                    "h-6 w-6 " +
                    (worst === "malicious"
                      ? "text-critical"
                      : worst === "suspicious"
                        ? "text-high"
                        : "text-fg-subtle")
                  }
                />
                <div>
                  <div className="text-sm text-fg-subtle">
                    Report for <span className="font-mono text-fg">{ran}</span>
                  </div>
                  <div className="text-lg font-semibold text-fg">
                    {result.iocs.length} indicator{result.iocs.length !== 1 && "s"} ·{" "}
                    {result.affected_hosts.length} affected host
                    {result.affected_hosts.length !== 1 && "s"}
                  </div>
                </div>
              </div>
              {worst && <VerdictBadge verdict={worst} />}
            </CardContent>
          </Card>

          {result.iocs.map((e, i) => (
            <IndicatorReport
              key={`${e.ioc.type}:${e.ioc.value}:${i}`}
              enriched={e}
              edrHits={result.edr_hits.filter(
                (h) => h.ioc.value.toLowerCase() === e.ioc.value.toLowerCase(),
              )}
            />
          ))}

          {result.related_investigations.length > 0 && (
            <RelatedCases cases={result.related_investigations} />
          )}

          <div className="flex justify-end">
            <Button
              variant="secondary"
              onClick={() => navigate(`/threat-intel?q=${encodeURIComponent(ran)}`)}
            >
              <History className="mr-1 h-4 w-4" /> Open in Threat Intelligence
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function IndicatorReport({
  enriched,
  edrHits,
}: {
  enriched: EnrichedIOC;
  edrHits: HuntResult["edr_hits"];
}) {
  const { ioc, verdict, confidence, sources, threat_actors, sightings } = enriched;
  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          <Badge>{ioc.type}</Badge>
          <span className="break-all font-mono text-sm text-fg">{ioc.value}</span>
          <CopyButton value={ioc.value} />
        </CardTitle>
        <div className="flex items-center gap-2">
          <VerdictBadge verdict={verdict} />
          <span className="text-xs text-fg-subtle">
            {Math.round(confidence * 100)}% confidence
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 pt-0">
        {/* Per-source verdicts */}
        <div>
          <div className="mb-1.5 text-xs font-semibold uppercase text-fg-subtle">
            Sources ({sources.length})
          </div>
          {sources.length ? (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
                  <tr>
                    <th className="px-3 py-2 font-medium">Source</th>
                    <th className="px-3 py-2 font-medium">Verdict</th>
                    <th className="px-3 py-2 font-medium">Score</th>
                    <th className="px-3 py-2 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {sources.map((s, i) => (
                    <tr key={`${s.source}:${i}`}>
                      <td className="px-3 py-2 font-medium text-fg">{s.source}</td>
                      <td className="px-3 py-2">
                        <VerdictBadge verdict={s.verdict} />
                      </td>
                      <td className="px-3 py-2 text-fg-subtle">
                        {Math.round(s.score * 100)}
                      </td>
                      <td className="px-3 py-2 text-fg-subtle">{s.detail ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-fg-subtle">
              No source returned a verdict for this indicator.
            </p>
          )}
        </div>

        {/* Threat actors + sightings */}
        {(threat_actors.length > 0 || sightings > 0) && (
          <div className="flex flex-wrap items-center gap-3 text-xs text-fg-subtle">
            {sightings > 0 && (
              <span className="inline-flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" /> {sightings} sighting
                {sightings !== 1 && "s"}
              </span>
            )}
            {threat_actors.map((a) => (
              <Badge key={a} tone="high">
                {a}
              </Badge>
            ))}
          </div>
        )}

        {/* EDR on-host sightings */}
        {edrHits.length > 0 && (
          <div>
            <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase text-critical">
              <Crosshair className="h-3.5 w-3.5" /> Observed on {edrHits.length} host
              {edrHits.length !== 1 && "s"} (EDR)
            </div>
            <div className="space-y-1">
              {edrHits.map((h, i) => (
                <div
                  key={`${h.host}:${i}`}
                  className="rounded-md border border-critical/30 bg-critical/5 p-2 text-xs"
                >
                  <span className="font-mono text-fg">{h.host}</span>
                  {h.user && <span className="text-fg-subtle"> · {h.user}</span>}
                  {h.process && (
                    <span className="text-fg-subtle"> · {h.process}</span>
                  )}
                  <div className="text-fg-subtle">{h.detail}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
