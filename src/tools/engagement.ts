import * as fs from "node:fs/promises";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { EngagementMetadata, IndexEntry } from "../types.js";
import {
  readJSON,
  writeJSON,
  ensureDir,
  getEngagementDir,
  getMetadataPath,
  getIndex,
  updateIndexEntry,
  setActiveEngagement,
  clearActiveEngagement,
  requireActiveEngagement,
  getActiveEngagementId,
  resolveDataDir,
} from "../storage/index.js";
import { renderFindings } from "../render/findings.js";
import { renderHost } from "../render/host.js";
import { writeFileAtomic } from "../storage/engine.js";

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);
}

function now(): string {
  return new Date().toISOString();
}

function makeEmptyMetadata(id: string, target: string, scope: string[], roe: string): EngagementMetadata {
  const ts = now();
  return {
    id,
    target,
    scope,
    rules_of_engagement: roe,
    status: "active",
    created_at: ts,
    updated_at: ts,
    executive_summary: "",
    attack_path: [],
    findings: [],
    hosts: [],
    credentials: [],
    dead_ends: [],
    todos: [],
    evidence_index: [],
    command_log: [],
    schema_version: 1,
  };
}

function buildIndexEntry(meta: EngagementMetadata): IndexEntry {
  return {
    id: meta.id,
    target: meta.target,
    status: meta.status,
    created_at: meta.created_at,
    updated_at: meta.updated_at,
    finding_count: meta.findings.length,
    host_count: meta.hosts.length,
    credential_count: meta.credentials.length,
    command_count: meta.command_log.length,
  };
}

// ── Business logic ──

export async function createEngagement(params: {
  target: string;
  scope: string[];
  rules_of_engagement?: string;
}): Promise<EngagementMetadata> {
  const datePrefix = new Date().toISOString().slice(0, 10);
  const slug = slugify(params.target);
  let id = `${datePrefix}-${slug}`;

  // Handle collisions
  const index = await getIndex();
  if (index.some((e) => e.id === id)) {
    let suffix = 2;
    while (index.some((e) => e.id === `${id}-${suffix}`)) {
      suffix++;
    }
    id = `${id}-${suffix}`;
  }

  const engDir = getEngagementDir(id);
  await ensureDir(engDir);
  await ensureDir(path.join(engDir, "evidence"));
  await ensureDir(path.join(engDir, "hosts"));

  const meta = makeEmptyMetadata(id, params.target, params.scope, params.rules_of_engagement || "");
  await writeJSON(getMetadataPath(id), meta);
  await updateIndexEntry(buildIndexEntry(meta));
  await setActiveEngagement(id);

  // Initial render
  const findingsMd = renderFindings(meta);
  await writeFileAtomic(path.join(engDir, "FINDINGS.md"), findingsMd);

  return meta;
}

export async function listEngagements(): Promise<(IndexEntry & { is_current: boolean })[]> {
  const index = await getIndex();
  const currentId = await getActiveEngagementId();
  return index.map((e) => ({ ...e, is_current: e.id === currentId }));
}

export async function resumeEngagement(id: string): Promise<{ metadata: EngagementMetadata; open_todos: number }> {
  const metaPath = getMetadataPath(id);
  try {
    await fs.access(metaPath);
  } catch {
    throw Object.assign(new Error(`Engagement '${id}' not found.`), { code: "engagement_not_found" });
  }

  const meta = await readJSON<EngagementMetadata>(metaPath, null as unknown as EngagementMetadata);
  await setActiveEngagement(id);

  const openTodos = meta.todos.filter((t) => t.status === "pending").length;
  return { metadata: meta, open_todos: openTodos };
}

export async function engagementStatus(): Promise<{
  id: string;
  target: string;
  status: string;
  findings_by_severity: Record<string, number>;
  host_count: number;
  credential_count: number;
  evidence_count: number;
  command_count: number;
  open_todos: number;
  recent_attack_path: { step: number; description: string }[];
}> {
  const id = await requireActiveEngagement();
  const meta = await readJSON<EngagementMetadata>(getMetadataPath(id), null as unknown as EngagementMetadata);

  const findingsBySeverity: Record<string, number> = {};
  for (const f of meta.findings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
  }

  return {
    id: meta.id,
    target: meta.target,
    status: meta.status,
    findings_by_severity: findingsBySeverity,
    host_count: meta.hosts.length,
    credential_count: meta.credentials.length,
    evidence_count: meta.evidence_index.length,
    command_count: meta.command_log.length,
    open_todos: meta.todos.filter((t) => t.status === "pending").length,
    recent_attack_path: meta.attack_path.slice(-5).map((s) => ({ step: s.step, description: s.description })),
  };
}

export async function closeEngagement(params: {
  status?: "completed" | "paused";
  executive_summary?: string;
}): Promise<{ id: string; status: string }> {
  const id = await requireActiveEngagement();
  const metaPath = getMetadataPath(id);
  const meta = await readJSON<EngagementMetadata>(metaPath, null as unknown as EngagementMetadata);

  meta.status = params.status || "completed";
  meta.updated_at = now();
  if (params.executive_summary) {
    meta.executive_summary = params.executive_summary;
  }

  await writeJSON(metaPath, meta);
  await updateIndexEntry(buildIndexEntry(meta));
  await clearActiveEngagement();

  // Final render
  const engDir = getEngagementDir(id);
  await writeFileAtomic(path.join(engDir, "FINDINGS.md"), renderFindings(meta));
  for (const host of meta.hosts) {
    await writeFileAtomic(path.join(engDir, "hosts", `${host.ip}.md`), renderHost(host));
  }

  return { id: meta.id, status: meta.status };
}

// ── Helpers for other tools ──

export async function loadActiveMetadata(): Promise<EngagementMetadata> {
  const id = await requireActiveEngagement();
  return readJSON<EngagementMetadata>(getMetadataPath(id), null as unknown as EngagementMetadata);
}

export async function saveMetadataAndRender(meta: EngagementMetadata): Promise<void> {
  meta.updated_at = now();
  await writeJSON(getMetadataPath(meta.id), meta);
  await updateIndexEntry(buildIndexEntry(meta));

  const engDir = getEngagementDir(meta.id);
  await writeFileAtomic(path.join(engDir, "FINDINGS.md"), renderFindings(meta));
}

export { buildIndexEntry };

// ── MCP registration ──

export function registerEngagementTools(server: McpServer): void {
  server.tool(
    "engagement_create",
    "Create a new pentest engagement with target and scope",
    {
      target: z.string().describe("Target name or identifier"),
      scope: z.array(z.string()).describe("In-scope IP ranges, domains, or URLs"),
      rules_of_engagement: z.string().optional().describe("Rules of engagement / constraints"),
    },
    async (args) => {
      const result = await createEngagement(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "engagement_list",
    "List all engagements",
    {},
    async () => {
      const result = await listEngagements();
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "engagement_resume",
    "Resume an existing engagement by ID",
    {
      id: z.string().describe("Engagement ID to resume"),
    },
    async (args) => {
      const result = await resumeEngagement(args.id);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "engagement_status",
    "Get status summary of the active engagement",
    {},
    async () => {
      const result = await engagementStatus();
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "engagement_close",
    "Close the active engagement",
    {
      status: z.enum(["completed", "paused"]).optional().describe("Final status (default: completed)"),
      executive_summary: z.string().optional().describe("Final executive summary"),
    },
    async (args) => {
      const result = await closeEngagement(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
