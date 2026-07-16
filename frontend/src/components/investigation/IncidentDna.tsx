/**
 * Incident DNA — the typed fingerprints of this incident (infrastructure,
 * malware, TTP, identity, threat, campaign, incident) and any prior incidents
 * that fingerprint-match it, per dimension. Backed by package.incident_dna and
 * package.dna_matches.
 */
import { Link } from "react-router-dom";
import { Dna, Fingerprint as FpIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { FingerprintMatch, IncidentDNA } from "@/types/api";

export function IncidentDna({
  dna,
  matches,
}: {
  dna: IncidentDNA;
  matches: FingerprintMatch[];
}) {
  const populated = dna.fingerprints.filter((f) => f.hash);
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Dna className="h-4 w-4 text-accent" />
          Incident DNA
          <span className="text-xs text-fg-subtle">
            {populated.length}/{dna.fingerprints.length} fingerprints
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pt-0">
        {/* Fingerprints */}
        <div className="grid gap-2 sm:grid-cols-2">
          {dna.fingerprints.map((f) => (
            <div
              key={f.kind}
              className={`rounded-md border border-border p-2 ${f.hash ? "" : "opacity-50"}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5 text-sm font-medium text-fg">
                  <FpIcon className="h-3.5 w-3.5 text-fg-subtle" />
                  {f.kind}
                </span>
                <span className="font-mono text-xs text-fg-subtle">
                  {f.hash || "—"}
                </span>
              </div>
              <p className="mt-0.5 text-xs text-fg-subtle">{f.label}</p>
            </div>
          ))}
        </div>

        {/* Fingerprint matches */}
        {matches.length > 0 && (
          <div>
            <div className="mb-1.5 text-xs font-semibold uppercase text-fg-subtle">
              Matches prior incidents
            </div>
            <div className="space-y-2">
              {matches.map((m) => (
                <div
                  key={m.investigation_id}
                  className="rounded-md border border-border p-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Link
                      to={`/investigations/${m.investigation_id}`}
                      className="text-sm font-medium text-fg hover:text-info hover:underline"
                    >
                      {m.title || m.investigation_id}
                    </Link>
                    <Badge tone="info">
                      {Math.round(m.overall_similarity * 100)}% match
                    </Badge>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {Object.entries(m.dimension_similarity).map(([dim, sim]) => (
                      <span
                        key={dim}
                        className="rounded bg-[#172033] px-1.5 py-0.5 text-xs text-fg-subtle"
                        title={(m.shared[dim] ?? []).join(", ")}
                      >
                        {dim} {Math.round(sim * 100)}%
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
