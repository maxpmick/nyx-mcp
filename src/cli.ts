#!/usr/bin/env node

import { Command } from "commander";
import { startMcpServer } from "./serve.js";
import {
  createEngagement,
  listEngagements,
  engagementStatus,
} from "./tools/engagement.js";
import { ingestToolOutput } from "./tools/ingest.js";
import { logCommand } from "./tools/commandLog.js";
import { saveEvidence } from "./tools/evidence.js";
import { getParser } from "./parsers/index.js";
import { requireActiveEngagement } from "./storage/index.js";

const VERSION = "1.0.0";

const program = new Command();

program
  .name("nyx-memory")
  .description("Structured pentest engagement memory for the Nyx autonomous agent")
  .version(VERSION);

// ── serve ──
program
  .command("serve")
  .description("Start the MCP server (stdio transport)")
  .action(async () => {
    await startMcpServer();
  });

// ── create ──
program
  .command("create")
  .description("Create a new engagement")
  .requiredOption("--target <target>", "Target name or identifier")
  .requiredOption("--scope <scope...>", "In-scope ranges/domains")
  .option("--roe <rules>", "Rules of engagement")
  .action(async (opts) => {
    const result = await createEngagement({
      target: opts.target,
      scope: opts.scope,
      rules_of_engagement: opts.roe,
    });
    console.log(`Created engagement: ${result.id}`);
    console.log(`Target: ${result.target}`);
    console.log(`Scope: ${result.scope.join(", ")}`);
  });

// ── list ──
program
  .command("list")
  .description("List all engagements")
  .option("--status <status>", "Filter by status")
  .action(async (opts) => {
    let entries = await listEngagements();
    if (opts.status) {
      entries = entries.filter((e) => e.status === opts.status);
    }
    if (entries.length === 0) {
      console.log("No engagements found.");
      return;
    }
    for (const e of entries) {
      const marker = e.is_current ? " *" : "";
      console.log(
        `${e.id}${marker} | ${e.target} | ${e.status} | F:${e.finding_count} H:${e.host_count} C:${e.credential_count} CMD:${e.command_count}`
      );
    }
  });

// ── status ──
program
  .command("status")
  .description("Show active engagement status")
  .option("--quiet", "Exit 0 if active, 1 if not (no output)")
  .action(async (opts) => {
    if (opts.quiet) {
      try {
        await requireActiveEngagement();
        process.exit(0);
      } catch {
        process.exit(1);
      }
    }
    const status = await engagementStatus();
    console.log(`Engagement: ${status.id}`);
    console.log(`Target: ${status.target}`);
    console.log(`Status: ${status.status}`);
    console.log(`Hosts: ${status.host_count} | Findings: ${JSON.stringify(status.findings_by_severity)} | Creds: ${status.credential_count}`);
    console.log(`Evidence: ${status.evidence_count} | Commands: ${status.command_count} | Open TODOs: ${status.open_todos}`);
    if (status.recent_attack_path.length > 0) {
      console.log("Recent attack path:");
      for (const s of status.recent_attack_path) {
        console.log(`  ${s.step}. ${s.description}`);
      }
    }
  });

// ── log ──
program
  .command("log")
  .description("Read stdin, save as evidence + command_log entry")
  .option("--tool <tool>", "Tool name")
  .option("--target <target>", "Target")
  .option("--command <command>", "Command that was run")
  .option("--started-at <ts>", "ISO timestamp when command started")
  .option("--duration <seconds>", "Duration in seconds", parseFloat)
  .option("--exit-code <code>", "Exit code", parseInt)
  .option("--filename <name>", "Evidence filename")
  .option("--no-parse", "Skip auto-parsing")
  .action(async (opts) => {
    // Read stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    const content = Buffer.concat(chunks).toString("utf-8");

    const tool = opts.tool || "unknown";
    const target = opts.target || "";
    const command = opts.command || `${tool} (piped)`;
    const filename = opts.filename || `${tool}-${Date.now()}.log`;
    const startedAt = opts.startedAt || new Date().toISOString();
    const finishedAt = new Date().toISOString();

    // Save evidence
    await saveEvidence({
      filename,
      content,
      description: `${tool} output captured via CLI`,
    });

    // Log command
    const entry = await logCommand({
      command,
      tool,
      target,
      started_at: startedAt,
      finished_at: finishedAt,
      duration_seconds: opts.duration ?? null,
      exit_code: opts.exitCode ?? null,
      evidence_file: filename,
      parsed: false,
      source: "cli",
    });

    // Auto-parse if parser available and not disabled
    if (opts.parse !== false) {
      const parser = getParser(tool);
      if (parser) {
        try {
          await ingestToolOutput({ tool, file: "-", target });
        } catch {
          // Auto-parse failure is non-fatal
        }
      }
    }

    console.log(`Logged: ${entry.id} | Evidence: ${filename}`);
  });

// ── ingest ──
program
  .command("ingest")
  .description("Parse and ingest structured tool output")
  .requiredOption("--tool <tool>", "Tool name (nmap, masscan, gobuster, nikto)")
  .requiredOption("--file <file>", "Path to tool output file")
  .option("--target <target>", "Target host IP")
  .action(async (opts) => {
    const result = await ingestToolOutput({
      tool: opts.tool,
      file: opts.file,
      target: opts.target,
    });
    console.log(`Ingested: ${result.hosts_discovered} hosts, ${result.services_added} services, ${result.findings_added} findings`);
  });

program.parseAsync().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
