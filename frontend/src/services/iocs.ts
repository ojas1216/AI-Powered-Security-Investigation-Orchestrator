import { http } from "./http";
import type { EnrichedIOC } from "@/types/api";

export async function extractAndEnrich(text: string, enrich = true): Promise<EnrichedIOC[]> {
  const { data } = await http.post<EnrichedIOC[]>("/iocs/extract", { text, enrich });
  return data;
}
