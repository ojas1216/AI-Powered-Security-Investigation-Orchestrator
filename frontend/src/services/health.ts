import { http } from "./http";

export interface HealthStatus {
  status: string;
  version?: string;
  env?: string;
  connector_mode?: string;
}

export async function getHealth(): Promise<HealthStatus> {
  const { data } = await http.get<HealthStatus>("/healthz");
  return data;
}

export async function getReadiness(): Promise<HealthStatus> {
  const { data } = await http.get<HealthStatus>("/readyz");
  return data;
}
