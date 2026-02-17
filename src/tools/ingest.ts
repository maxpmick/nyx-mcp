import * as fs from "node:fs/promises";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getParser, getSupportedParsers } from "../parsers/index.js";
import { discoverHost, updateHost } from "./hosts.js";
import { addFinding } from "./findings.js";
import { saveEvidence } from "./evidence.js";
import { loadActiveMetadata } from "./engagement.js";

export async function ingestToolOutput(params: {
  tool: string;
  file: string;
  target?: string;
}): Promise<{
  hosts_discovered: number;
  services_added: number;
  findings_added: number;
  evidence_saved: boolean;
}> {
  const parser = getParser(params.tool);
  if (!parser) {
    throw Object.assign(
      new Error(`No parser for tool '${params.tool}'. Supported: ${getSupportedParsers().join(", ")}`),
      { code: "unsupported_tool" }
    );
  }

  let content: string;
  try {
    content = await fs.readFile(params.file, "utf-8");
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw Object.assign(new Error(`File not found: ${params.file}`), { code: "file_not_found" });
    }
    throw err;
  }

  const result = await parser.parse(content);

  let hostsDiscovered = 0;
  let servicesAdded = 0;
  let findingsAdded = 0;

  // Process discovered hosts
  for (const hostData of result.hosts) {
    await discoverHost({
      ip: hostData.ip,
      hostname: hostData.hostname,
      os: hostData.os,
      services: hostData.services?.map((s) => ({
        port: s.port,
        proto: s.proto,
        service: s.service,
        version: s.version,
        notes: s.notes,
      })),
    });
    hostsDiscovered++;
    servicesAdded += hostData.services?.length || 0;
  }

  // Process findings
  for (const findingData of result.findings) {
    await addFinding({
      host: findingData.host,
      vulnerability: findingData.vulnerability,
      severity: findingData.severity,
      cvss: findingData.cvss,
      status: findingData.status,
      notes: findingData.notes,
    });
    findingsAdded++;
  }

  // If parser produced raw_text (e.g., gobuster), append to host's enumeration section
  if (result.raw_text && params.target) {
    try {
      await updateHost({
        ip: params.target,
        section: "enumeration",
        content: `### ${params.tool} output\n\n${result.raw_text}`,
      });
    } catch {
      // Host might not exist yet — that's fine
    }
  }

  // Copy file to evidence dir
  const filename = `${params.tool}-${path.basename(params.file)}`;
  await saveEvidence({
    filename,
    content,
    description: `${params.tool} output: ${path.basename(params.file)}`,
  });

  return {
    hosts_discovered: hostsDiscovered,
    services_added: servicesAdded,
    findings_added: findingsAdded,
    evidence_saved: true,
  };
}

export function registerIngestTools(server: McpServer): void {
  server.tool(
    "ingest_tool_output",
    "Parse and ingest structured tool output (nmap, masscan, gobuster, nikto)",
    {
      tool: z.string().describe(`Tool name (${getSupportedParsers().join(", ")})`),
      file: z.string().describe("Path to the tool output file"),
      target: z.string().optional().describe("Target host IP (for appending raw results)"),
    },
    async (args) => {
      const result = await ingestToolOutput(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
