/**
 * Natural-language case search — semantic search over completed investigations
 * ("credential phishing against finance"). Backed by POST /search/cases.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Search } from "lucide-react";
import { searchCases } from "@/services/platform";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState } from "@/components/common/states";
import { VerdictBadge } from "@/components/common/badges";
import type { CaseSearchHit } from "@/types/api";

export function CaseSearchPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<CaseSearchHit[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function run() {
    if (!query.trim()) return;
    setBusy(true);
    setError("");
    try {
      setHits(await searchCases(query));
    } catch {
      setError("Search failed.");
      setHits(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Case Search"
        description="Semantic, natural-language search across completed investigations."
      />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
        className="mb-5 flex gap-2"
      >
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="e.g. invoice phishing against finance, ransomware shadow-copy deletion"
            className="pl-9"
            autoFocus
          />
        </div>
        <Button type="submit" disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Search"}
        </Button>
      </form>

      {error && <ErrorState message={error} onRetry={run} />}
      {hits && hits.length === 0 && !error && (
        <EmptyState title="No matching cases" description="Try different wording." />
      )}
      {hits && hits.length > 0 && (
        <div className="space-y-2">
          {hits.map((h) => (
            <Card
              key={h.investigation_id}
              className="cursor-pointer transition hover:border-accent/40"
              onClick={() => navigate(`/investigations/${h.investigation_id}`)}
            >
              <CardContent className="flex items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="truncate font-medium text-fg">{h.title}</div>
                  <div className="truncate text-xs text-fg-subtle">{h.snippet}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className="text-xs text-fg-subtle">
                    {Math.round(h.score * 100)}% match
                  </span>
                  <VerdictBadge verdict={h.verdict} />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
