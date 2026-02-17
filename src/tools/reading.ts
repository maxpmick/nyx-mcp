import * as fs from "node:fs/promises";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { EngagementMetadata } from "../types.js";
import { loadActiveMetadata } from "./engagement.js";
import {
  getEngagementDir,
  getIndex,
  readJSON,
  getMetadataPath,
} from "../storage/index.js";
import { renderFindings } from "../render/findings.js";
import { renderHost } from "../render/host.js";

const WHAT_OPTIONS = [
  "findings",
  "host",
  "evidence_index",
  "todos",
  "attack_path",
  "dead_ends",
  "credentials",
  "command_log",
  "search",
] as const;

type WhatOption = (typeof WHAT_OPTIONS)[number];

function searchMetadata(meta: EngagementMetadata, query: string): string[] {
  const q = query.toLowerCase();
  const results: string[] = [];

  for (const f of meta.findings) {
    const text = `${f.id} ${f.host} ${f.vulnerability} ${f.notes}`;
    if (text.toLowerCase().includes(q)) {
      results.push(`[Finding ${f.id}] ${f.vulnerability} on ${f.host} (${f.severity})`);
    }
  }
  for (const h of meta.hosts) {
    const text = `${h.ip} ${h.hostname} ${h.os} ${h.enumeration} ${h.vulnerabilities} ${h.exploitation}`;
    if (text.toLowerCase().includes(q)) {
      results.push(`[Host] ${h.ip} (${h.hostname || "unknown"})`);
    }
  }
  for (const c of meta.credentials) {
    const text = `${c.id} ${c.source} ${c.username}`;
    if (text.toLowerCase().includes(q)) {
      results.push(`[Credential ${c.id}] ${c.username} from ${c.source}`);
    }
  }
  for (const d of meta.dead_ends) {
    const text = `${d.technique} ${d.target} ${d.reason}`;
    if (text.toLowerCase().includes(q)) {
      results.push(`[Dead End] ${d.technique} on ${d.target}`);
    }
  }
  for (const step of meta.attack_path) {
    if (step.description.toLowerCase().includes(q)) {
      results.push(`[Attack Path Step ${step.step}] ${step.description}`);
    }
  }
  for (const cmd of meta.command_log) {
    const text = `${cmd.id} ${cmd.command} ${cmd.tool} ${cmd.target}`;
    if (text.toLowerCase().includes(q)) {
      results.push(`[Command ${cmd.id}] ${cmd.tool}: ${cmd.command.slice(0, 80)}`);
    }
  }

  return results;
}

export async function readNotes(params: {
  what: WhatOption;
  host_ip?: string;
  query?: string;
  scope?: "current" | "all";
}): Promise<string> {
  if (params.what === "search" && params.scope === "all") {
    // Cross-engagement search
    if (!params.query) return "No query provided for search.";
    const index = await getIndex();
    const allResults: string[] = [];
    for (const entry of index) {
      const meta = await readJSON<EngagementMetadata>(
        getMetadataPath(entry.id),
        null as unknown as EngagementMetadata
      );
      if (!meta) continue;
      const matches = searchMetadata(meta, params.query);
      if (matches.length > 0) {
        allResults.push(`\n## ${entry.id} (${entry.target})\n${matches.join("\n")}`);
      }
    }
    return allResults.length > 0 ? allResults.join("\n") : "No results found.";
  }

  const meta = await loadActiveMetadata();

  switch (params.what) {
    case "findings":
      return renderFindings(meta);

    case "host": {
      if (!params.host_ip) return "Error: host_ip is required when reading a host.";
      const host = meta.hosts.find((h) => h.ip === params.host_ip);
      if (!host) return `Host '${params.host_ip}' not found.`;
      return renderHost(host);
    }

    case "evidence_index": {
      if (meta.evidence_index.length === 0) return "No evidence files indexed.";
      return meta.evidence_index
        .map((e) => `- ${e.filename}: ${e.description}${e.related_finding_id ? ` (${e.related_finding_id})` : ""}`)
        .join("\n");
    }

    case "todos": {
      if (meta.todos.length === 0) return "No TODOs.";
      const pending = meta.todos.filter((t) => t.status === "pending");
      const completed = meta.todos.filter((t) => t.status === "completed");
      let result = "";
      if (pending.length > 0) {
        result += "## Pending\n" + pending.map((t) => `- [${t.priority}] ${t.id}: ${t.description}`).join("\n") + "\n";
      }
      if (completed.length > 0) {
        result +=
          "\n## Completed\n" + completed.map((t) => `- ${t.id}: ${t.description} (${t.completed_at})`).join("\n") + "\n";
      }
      return result;
    }

    case "attack_path": {
      if (meta.attack_path.length === 0) return "No attack path documented.";
      return meta.attack_path.map((s) => `${s.step}. ${s.description} (${s.timestamp})`).join("\n");
    }

    case "dead_ends": {
      if (meta.dead_ends.length === 0) return "No dead ends recorded.";
      return meta.dead_ends
        .map((d) => `- ${d.technique} on ${d.target}: ${d.reason} (${d.timestamp})`)
        .join("\n");
    }

    case "credentials": {
      if (meta.credentials.length === 0) return "No credentials captured.";
      return meta.credentials
        .map(
          (c) =>
            `- ${c.id}: ${c.username} (${c.cred_type}) from ${c.source} — ${c.verified ? "verified" : "unverified"}`
        )
        .join("\n");
    }

    case "command_log": {
      if (meta.command_log.length === 0) return "No commands logged.";
      return meta.command_log
        .map(
          (c) =>
            `- ${c.id} [${c.tool}] ${c.command.slice(0, 100)}${c.command.length > 100 ? "..." : ""} → ${c.target} (exit ${c.exit_code ?? "?"})`
        )
        .join("\n");
    }

    case "search": {
      if (!params.query) return "No query provided for search.";
      const results = searchMetadata(meta, params.query);
      return results.length > 0 ? results.join("\n") : "No results found.";
    }
  }
}

export function registerReadingTools(server: McpServer): void {
  server.tool(
    "notes_read",
    "Read engagement notes, findings, hosts, or search across data",
    {
      what: z.enum(WHAT_OPTIONS).describe("What to read"),
      host_ip: z.string().optional().describe("Host IP (required when what='host')"),
      query: z.string().optional().describe("Search query (required when what='search')"),
      scope: z
        .enum(["current", "all"])
        .optional()
        .describe("Search scope: 'current' engagement or 'all' (default: current)"),
    },
    async (args) => {
      const result = await readNotes(args);
      return { content: [{ type: "text" as const, text: result }] };
    }
  );
}
