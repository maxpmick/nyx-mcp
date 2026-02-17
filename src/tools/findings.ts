import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Finding } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const STATUSES = ["confirmed", "potential", "exploited", "false_positive"] as const;

function now(): string {
  return new Date().toISOString();
}

function nextFindingId(existing: Finding[]): string {
  let max = 0;
  for (const f of existing) {
    const n = parseInt(f.id.replace("F-", ""), 10);
    if (n > max) max = n;
  }
  return `F-${String(max + 1).padStart(3, "0")}`;
}

export async function addFinding(params: {
  host: string;
  vulnerability: string;
  severity: (typeof SEVERITIES)[number];
  cvss?: number;
  status?: (typeof STATUSES)[number];
  evidence_file?: string;
  notes?: string;
}): Promise<Finding> {
  const meta = await loadActiveMetadata();
  const id = nextFindingId(meta.findings);

  if (params.cvss !== undefined && (params.cvss < 0 || params.cvss > 10)) {
    throw Object.assign(new Error("CVSS must be between 0.0 and 10.0"), { code: "invalid_cvss" });
  }

  const finding: Finding = {
    id,
    host: params.host,
    vulnerability: params.vulnerability,
    severity: params.severity,
    cvss: params.cvss ?? null,
    status: params.status || "confirmed",
    evidence_file: params.evidence_file || null,
    notes: params.notes || "",
    created_at: now(),
    updated_at: now(),
  };

  meta.findings.push(finding);
  await saveMetadataAndRender(meta);
  return finding;
}

export async function updateFinding(params: {
  id: string;
  severity?: (typeof SEVERITIES)[number];
  cvss?: number;
  status?: (typeof STATUSES)[number];
  evidence_file?: string;
  notes?: string;
}): Promise<Finding> {
  const meta = await loadActiveMetadata();
  const finding = meta.findings.find((f) => f.id === params.id);
  if (!finding) {
    throw Object.assign(new Error(`Finding '${params.id}' not found.`), { code: "finding_not_found" });
  }

  if (params.severity) finding.severity = params.severity;
  if (params.cvss !== undefined) {
    if (params.cvss < 0 || params.cvss > 10) {
      throw Object.assign(new Error("CVSS must be between 0.0 and 10.0"), { code: "invalid_cvss" });
    }
    finding.cvss = params.cvss;
  }
  if (params.status) finding.status = params.status;
  if (params.evidence_file) finding.evidence_file = params.evidence_file;
  if (params.notes) {
    // Append notes, not replace
    finding.notes = finding.notes ? `${finding.notes}\n\n${params.notes}` : params.notes;
  }
  finding.updated_at = now();

  await saveMetadataAndRender(meta);
  return finding;
}

export function registerFindingTools(server: McpServer): void {
  server.tool(
    "finding_add",
    "Add a new finding to the active engagement",
    {
      host: z.string().describe("Target host IP or hostname"),
      vulnerability: z.string().describe("Vulnerability name/title"),
      severity: z.enum(SEVERITIES).describe("Severity level"),
      cvss: z.number().min(0).max(10).optional().describe("CVSS score (0.0-10.0)"),
      status: z.enum(STATUSES).optional().describe("Finding status (default: confirmed)"),
      evidence_file: z.string().optional().describe("Associated evidence filename"),
      notes: z.string().optional().describe("Additional notes"),
    },
    async (args) => {
      const result = await addFinding(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "finding_update",
    "Update an existing finding",
    {
      id: z.string().describe("Finding ID (e.g., F-001)"),
      severity: z.enum(SEVERITIES).optional().describe("Updated severity"),
      cvss: z.number().min(0).max(10).optional().describe("Updated CVSS score"),
      status: z.enum(STATUSES).optional().describe("Updated status"),
      evidence_file: z.string().optional().describe("Updated evidence filename"),
      notes: z.string().optional().describe("Notes to append"),
    },
    async (args) => {
      const result = await updateFinding(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
