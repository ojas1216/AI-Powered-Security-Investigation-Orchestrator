import { http } from "./http";
import type { EnrichedIOC, EDRHit, RelatedCase } from "@/types/api";

export interface HuntResult {
  iocs: EnrichedIOC[];
  edr_hits: EDRHit[];
  affected_hosts: string[];
  related_investigations: RelatedCase[];
}

/** Full-report pivot: TI enrichment + EDR hunt + case-memory recall in one call. */
export async function runHunt(input: {
  text?: string;
  indicators?: string[];
}): Promise<HuntResult> {
  const { data } = await http.post<HuntResult>("/hunts", input);
  return data;
}
