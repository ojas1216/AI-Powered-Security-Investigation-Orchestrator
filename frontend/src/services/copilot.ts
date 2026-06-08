import { http } from "./http";
import type { CopilotAnswer } from "@/types/api";

export async function askCopilot(
  investigationId: string,
  question: string,
): Promise<CopilotAnswer> {
  const { data } = await http.post<CopilotAnswer>("/copilot/ask", {
    investigation_id: investigationId,
    question,
  });
  return data;
}
