import type { RawAlert } from "@/services/investigations";

/** Demo alert payloads mirroring backend/seed/*. Used by the "Ingest sample"
 *  action so analysts can exercise the live pipeline without an upstream SIEM. */
export const SAMPLE_ALERTS: { id: string; label: string; payload: RawAlert }[] = [
  {
    id: "phishing-sentinel",
    label: "Phishing (Sentinel)",
    payload: {
      source: "sentinel",
      properties: {
        incidentNumber: "INC-204815",
        title: "Phishing email reported by user — suspicious invoice link",
        description:
          "Body contains hxxps://evil[.]com/pay and Invoice_8841.lnk; PowerShell spawned on WS-FIN-042.",
        severity: "high",
        entities: [
          { kind: "Account", accountName: "jdoe" },
          { kind: "Host", hostName: "WS-FIN-042" },
          { kind: "Ip", address: "45.155.205.99" },
        ],
      },
      message_id: "phish-0001",
    },
  },
  {
    id: "powershell-splunk",
    label: "Malicious PowerShell (Splunk)",
    payload: {
      source: "splunk",
      sid: "scheduler__admin__search__demo",
      result: {
        event_id: "ES-9931",
        search_name: "Endpoint - Malicious PowerShell Execution",
        description: "Encoded PowerShell contacting malware-c2.net from 45.155.205.99",
        urgency: "critical",
        src_ip: "45.155.205.99",
        user: "jdoe",
        dvc: "WS-FIN-042",
        process: "powershell.exe -enc aQB3AHIA",
      },
    },
  },
];
