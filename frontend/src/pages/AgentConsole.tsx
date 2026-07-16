/**
 * Agent Console — invoke any specialist agent on its own (the same agents the
 * autonomous loop composes). Pick an agent, supply a JSON payload, see the
 * typed result. Backed by GET /agents and POST /agents/{name}/run.
 */
import { useEffect, useMemo, useState } from "react";
import { Bot, Loader2, Play } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { listAgents, runAgent } from "@/services/platform";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { LoadingState, ErrorState } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import type { AgentResult } from "@/types/api";

const SAMPLE_PAYLOADS: Record<string, string> = {
  threat_intel: '{ "indicators": ["evil.com", "8.8.8.8"] }',
  ioc_extraction: '{ "text": "beacon to hxxps://evil[.]com/pay" }',
  detection: '{ "raw_text": "powershell -enc aQB3AHIA" }',
  edr_hunt: '{ "indicators": ["malware-c2.net"] }',
  mitre: '{ "signals": ["powershell -enc"], "has_malicious_url": true }',
  sigma_generator: '{ "title": "C2 beacon", "iocs": [] }',
  yara_generator: '{ "rule_name": "sample", "hashes": ["abc123"], "strings": ["MZ"] }',
  business_impact: '{ "affected_hosts": ["WS-FIN-1"], "verdict": "malicious", "risk_score": 90 }',
};

export function AgentConsolePage() {
  const { data: agents, isLoading, isError, refetch } = useQuery({
    queryKey: ["agents"],
    queryFn: listAgents,
  });
  const [selected, setSelected] = useState<string>("");
  const [payload, setPayload] = useState<string>("{}");
  const [result, setResult] = useState<AgentResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (agents?.length && !selected) {
      setSelected(agents[0].name);
    }
  }, [agents, selected]);

  useEffect(() => {
    if (selected) setPayload(SAMPLE_PAYLOADS[selected] ?? "{}");
  }, [selected]);

  const current = useMemo(
    () => agents?.find((a) => a.name === selected),
    [agents, selected],
  );

  async function run() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const parsed = JSON.parse(payload || "{}");
      setResult(await runAgent(selected, parsed));
    } catch (e: unknown) {
      setError(
        e instanceof SyntaxError
          ? "Payload is not valid JSON."
          : "Agent invocation failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (isLoading) return <LoadingState label="Loading agents…" />;
  if (isError || !agents)
    return <ErrorState message="Could not load agents." onRetry={refetch} />;

  return (
    <div>
      <PageHeader
        title="Agent Console"
        description="Invoke any specialist agent independently — the same agents the autonomous loop composes."
      />
      <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
        <Card className="h-fit">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Agents ({agents.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 pt-0">
            {agents.map((a) => (
              <button
                key={a.name}
                onClick={() => setSelected(a.name)}
                className={
                  "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm " +
                  (selected === a.name
                    ? "bg-accent/15 text-accent"
                    : "text-fg-subtle hover:bg-[#172033] hover:text-fg")
                }
              >
                <Bot className="h-3.5 w-3.5 shrink-0" />
                <span className="font-mono text-xs">{a.name}</span>
              </button>
            ))}
          </CardContent>
        </Card>

        <div className="space-y-4">
          {current && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">{current.name}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 pt-0">
                <p className="text-sm text-fg-subtle">{current.description}</p>
                {Object.keys(current.input_hint).length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(current.input_hint).map(([k, v]) => (
                      <Badge key={k} tone="neutral" title={v}>
                        {k}
                      </Badge>
                    ))}
                  </div>
                )}
                <Textarea
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  rows={5}
                  className="font-mono text-xs"
                  spellCheck={false}
                />
                {error && <p className="text-sm text-critical">{error}</p>}
                <Button onClick={run} disabled={busy}>
                  {busy ? (
                    <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="mr-1 h-4 w-4" />
                  )}
                  Run agent
                </Button>
              </CardContent>
            </Card>
          )}

          {result && (
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm">Result</CardTitle>
                <Badge tone={result.ok ? "low" : "critical"}>
                  {result.ok ? "ok" : "error"}
                </Badge>
              </CardHeader>
              <CardContent className="space-y-2 pt-0">
                <p className="text-sm text-fg">{result.summary}</p>
                <pre className="max-h-96 overflow-auto rounded-md border border-border bg-[#0d1526] p-3 text-xs text-fg-subtle">
                  {JSON.stringify(result.data, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
