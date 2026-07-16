/**
 * Multi-format detection export — generate deployable detections (Sigma, YARA,
 * Suricata, Splunk SPL, Sentinel KQL, Chronicle YARA-L, Elastic EQL, Wazuh,
 * Falcon) from this investigation's confirmed indicators, each with rationale
 * and estimated precision/recall. Backed by GET /detections/export/{id}.
 */
import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { exportDetections } from "@/services/platform";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CopyButton } from "@/components/common/CopyButton";
import type { GeneratedRule } from "@/types/api";

const LABELS: Record<string, string> = {
  sigma: "Sigma",
  yara: "YARA",
  suricata: "Suricata",
  splunk_spl: "Splunk SPL",
  sentinel_kql: "Sentinel KQL",
  chronicle_yaral: "Chronicle YARA-L",
  elastic_eql: "Elastic EQL",
  wazuh: "Wazuh",
  falcon: "Falcon",
};

export function DetectionExport({ investigationId }: { investigationId: string }) {
  const [rules, setRules] = useState<GeneratedRule[] | null>(null);
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setBusy(true);
    setError("");
    try {
      const r = await exportDetections(investigationId);
      setRules(r);
      setActive(0);
    } catch {
      setError("Could not generate detections.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">Multi-format detection export</CardTitle>
        <Button size="sm" variant="secondary" disabled={busy} onClick={load}>
          {busy ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Download className="mr-1 h-4 w-4" />}
          Generate
        </Button>
      </CardHeader>
      {error && <CardContent className="pt-0 text-sm text-critical">{error}</CardContent>}
      {rules && rules.length > 0 && (
        <CardContent className="space-y-3 pt-0">
          <div className="flex flex-wrap gap-1.5">
            {rules.map((r, i) => (
              <button
                key={r.format}
                onClick={() => setActive(i)}
                className={
                  "rounded-md px-2 py-1 text-xs font-medium " +
                  (i === active
                    ? "bg-accent text-white"
                    : "bg-[#172033] text-fg-subtle hover:text-fg")
                }
              >
                {LABELS[r.format] ?? r.format}
              </button>
            ))}
          </div>

          {rules[active] && (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-3 text-xs text-fg-subtle">
                <span>{rules[active].rationale}</span>
                <span>
                  precision{" "}
                  <span className="text-low">
                    {Math.round(rules[active].estimated_precision * 100)}%
                  </span>
                </span>
                <span>
                  recall{" "}
                  <span className="text-medium">
                    {Math.round(rules[active].estimated_recall * 100)}%
                  </span>
                </span>
                <CopyButton value={rules[active].rule} />
              </div>
              <pre className="max-h-96 overflow-auto rounded-md border border-border bg-[#0d1526] p-3 text-xs text-fg-subtle">
                {rules[active].rule}
              </pre>
            </div>
          )}
        </CardContent>
      )}
      {rules && rules.length === 0 && (
        <CardContent className="pt-0 text-sm text-fg-subtle">
          No confirmed indicators to build detections from.
        </CardContent>
      )}
    </Card>
  );
}
