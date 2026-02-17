import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackPathStep } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";

function now(): string {
  return new Date().toISOString();
}

export async function updateAttackPath(params: { description: string }): Promise<AttackPathStep> {
  const meta = await loadActiveMetadata();

  const step = meta.attack_path.length + 1;
  const entry: AttackPathStep = {
    step,
    description: params.description,
    timestamp: now(),
  };

  meta.attack_path.push(entry);
  await saveMetadataAndRender(meta);
  return entry;
}

export async function updateExecutiveSummary(params: { summary: string }): Promise<{ summary: string }> {
  const meta = await loadActiveMetadata();
  meta.executive_summary = params.summary;
  await saveMetadataAndRender(meta);
  return { summary: meta.executive_summary };
}

export function registerNarrativeTools(server: McpServer): void {
  server.tool(
    "attack_path_update",
    "Add a step to the attack path narrative",
    {
      description: z.string().describe("Description of the attack path step"),
    },
    async (args) => {
      const result = await updateAttackPath(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "executive_summary_update",
    "Update the executive summary",
    {
      summary: z.string().describe("New executive summary content"),
    },
    async (args) => {
      const result = await updateExecutiveSummary(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
