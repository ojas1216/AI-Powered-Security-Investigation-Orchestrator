import { useQuery } from "@tanstack/react-query";
import { getReadiness } from "@/services/health";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: getReadiness,
    refetchInterval: 20_000,
    retry: false,
  });
}
