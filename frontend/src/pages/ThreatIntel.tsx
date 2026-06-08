import { useMemo, useState } from "react";
import { Loader2, Sparkles } from "lucide-react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { extractAndEnrich } from "@/services/iocs";
import { useAudit } from "@/hooks/useAudit";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { IocTable } from "@/components/investigation/IocTable";
import { LoadingState } from "@/components/common/states";
import type { EnrichedIOC } from "@/types/api";

const SOURCES = ["VirusTotal", "AbuseIPDB", "GreyNoise", "OpenCTI", "MISP", "OTX"];

export function ThreatIntelPage() {
  const { data, isLoading } = useInvestigations();
  const audit = useAudit();
  const [text, setText] = useState("");
  const [results, setResults] = useState<EnrichedIOC[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const aggregated = useMemo(() => {
    const map = new Map<string, EnrichedIOC>();
    for (const inv of data ?? []) {
      for (const e of inv.iocs) {
        const key = `${e.ioc.type}:${e.ioc.value}`;
        const prev = map.get(key);
        if (!prev || e.confidence > prev.confidence) map.set(key, e);
      }
    }
    return [...map.values()].sort((a, b) => b.confidence - a.confidence);
  }, [data]);

  async function run() {
    setBusy(true);
    setError("");
    try {
      const r = await extractAndEnrich(text, true);
      setResults(r);
      audit("ioc.extract", `${r.length} indicators`);
    } catch {
      setError("Extraction failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader title="Threat Intelligence" description="Multi-source IOC correlation and enrichment" />

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {SOURCES.map((s) => (
          <Card key={s} className="p-3 text-center">
            <div className="text-xs font-medium text-fg">{s}</div>
            <div className="mt-1 text-[11px] text-low">connected</div>
          </Card>
        ))}
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>IOC Extractor & Enrichment</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste an email, log line, or alert text to extract & enrich IOCs (defanged input supported, e.g. hxxps://evil[.]com)…"
          />
          <div className="flex items-center gap-2">
            <Button size="sm" disabled={busy || !text.trim()} onClick={run}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
              Extract & Enrich
            </Button>
            {error && <span className="text-sm text-critical">{error}</span>}
          </div>
          {results && (
            <div className="pt-2">
              <IocTable iocs={results} />
            </div>
          )}
        </CardContent>
      </Card>

      <h2 className="mb-3 text-sm font-semibold text-fg">
        Correlated Indicators ({aggregated.length})
      </h2>
      {isLoading ? <LoadingState /> : <IocTable iocs={aggregated} />}
    </div>
  );
}
