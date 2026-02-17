import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { CommandEntry } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";

function now(): string {
  return new Date().toISOString();
}

function nextCmdId(existing: CommandEntry[]): string {
  let max = 0;
  for (const c of existing) {
    const n = parseInt(c.id.replace("CMD-", ""), 10);
    if (n > max) max = n;
  }
  return `CMD-${String(max + 1).padStart(3, "0")}`;
}

function detectTool(command: string): string {
  const firstToken = command.trim().split(/\s+/)[0];
  if (!firstToken) return "unknown";
  // Strip path prefix
  const base = firstToken.split("/").pop() || firstToken;
  return base;
}

export async function logCommand(params: {
  command: string;
  tool?: string;
  target?: string;
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
  exit_code?: number;
  evidence_file?: string;
  parsed?: boolean;
  source?: "mcp" | "cli" | "nyx-log";
}): Promise<CommandEntry> {
  const meta = await loadActiveMetadata();
  const id = nextCmdId(meta.command_log);

  const entry: CommandEntry = {
    id,
    command: params.command,
    tool: params.tool || detectTool(params.command),
    target: params.target || "",
    started_at: params.started_at || now(),
    finished_at: params.finished_at || now(),
    duration_seconds: params.duration_seconds ?? null,
    exit_code: params.exit_code ?? null,
    evidence_file: params.evidence_file || null,
    parsed: params.parsed ?? false,
    source: params.source || "mcp",
  };

  meta.command_log.push(entry);
  await saveMetadataAndRender(meta);
  return entry;
}

export function registerCommandLogTools(server: McpServer): void {
  server.tool(
    "command_log",
    "Log a command execution with metadata",
    {
      command: z.string().describe("The command that was executed"),
      tool: z.string().optional().describe("Tool name (auto-detected from command if not provided)"),
      target: z.string().optional().describe("Target of the command"),
      started_at: z.string().optional().describe("ISO timestamp when command started"),
      finished_at: z.string().optional().describe("ISO timestamp when command finished"),
      duration_seconds: z.number().optional().describe("Duration in seconds"),
      exit_code: z.number().optional().describe("Exit code"),
      evidence_file: z.string().optional().describe("Associated evidence filename"),
      parsed: z.boolean().optional().describe("Whether output was parsed"),
      source: z.enum(["mcp", "cli", "nyx-log"]).optional().describe("Source of the log entry"),
    },
    async (args) => {
      const result = await logCommand(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
