import * as fs from "node:fs/promises";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { EvidenceEntry } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";
import { getEngagementDir, ensureDir, writeFileAtomic } from "../storage/index.js";

function now(): string {
  return new Date().toISOString();
}

export async function saveEvidence(params: {
  filename: string;
  content: string;
  description?: string;
  related_finding_id?: string;
}): Promise<{ entry: EvidenceEntry; overwritten: boolean }> {
  // Validate filename — no path separators
  if (params.filename.includes("/") || params.filename.includes("\\")) {
    throw Object.assign(new Error("Filename must not contain path separators."), { code: "invalid_filename" });
  }

  const meta = await loadActiveMetadata();
  const engDir = getEngagementDir(meta.id);
  const evidenceDir = path.join(engDir, "evidence");
  await ensureDir(evidenceDir);

  const filePath = path.join(evidenceDir, params.filename);

  // Check overwrite
  let overwritten = false;
  try {
    await fs.access(filePath);
    overwritten = true;
  } catch {
    // File does not exist
  }

  await writeFileAtomic(filePath, params.content);

  // Add to evidence index (update existing or add new)
  const existingIdx = meta.evidence_index.findIndex((e) => e.filename === params.filename);
  const entry: EvidenceEntry = {
    filename: params.filename,
    description: params.description || params.filename,
    related_finding_id: params.related_finding_id || null,
    created_at: now(),
  };

  if (existingIdx >= 0) {
    meta.evidence_index[existingIdx] = entry;
  } else {
    meta.evidence_index.push(entry);
  }

  await saveMetadataAndRender(meta);
  return { entry, overwritten };
}

export function registerEvidenceTools(server: McpServer): void {
  server.tool(
    "evidence_save",
    "Save evidence content to a file and index it",
    {
      filename: z.string().describe("Filename (no path separators)"),
      content: z.string().describe("File content to save"),
      description: z.string().optional().describe("Description of the evidence"),
      related_finding_id: z.string().optional().describe("Related finding ID (e.g., F-001)"),
    },
    async (args) => {
      const result = await saveEvidence(args);
      const msg = result.overwritten
        ? `Evidence saved (overwritten existing): ${result.entry.filename}`
        : `Evidence saved: ${result.entry.filename}`;
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ message: msg, ...result }, null, 2) }],
      };
    }
  );
}
