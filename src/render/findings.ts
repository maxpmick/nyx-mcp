import type { EngagementMetadata, Finding } from "../types.js";

function severityOrder(s: string): number {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return order[s] ?? 5;
}

function severityBadge(s: string): string {
  const badges: Record<string, string> = {
    critical: "**CRITICAL**",
    high: "**HIGH**",
    medium: "MEDIUM",
    low: "LOW",
    info: "INFO",
  };
  return badges[s] || s.toUpperCase();
}

function findingsTable(findings: Finding[]): string {
  if (findings.length === 0) return "*No findings recorded yet.*\n";

  const sorted = [...findings].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));
  const lines = [
    "| ID | Host | Vulnerability | Severity | CVSS | Status |",
    "|---|---|---|---|---|---|",
  ];
  for (const f of sorted) {
    lines.push(
      `| ${f.id} | ${f.host} | ${f.vulnerability} | ${severityBadge(f.severity)} | ${f.cvss ?? "-"} | ${f.status} |`
    );
  }
  return lines.join("\n") + "\n";
}

function critHighFindings(findings: Finding[]): string {
  const critical = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  if (critical.length === 0) return "";

  const sorted = [...critical].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));
  let md = "## Critical & High Findings\n\n";
  for (const f of sorted) {
    md += `### ${f.id}: ${f.vulnerability}\n\n`;
    md += `- **Severity:** ${severityBadge(f.severity)}`;
    if (f.cvss !== null) md += ` (CVSS ${f.cvss})`;
    md += "\n";
    md += `- **Host:** ${f.host}\n`;
    md += `- **Status:** ${f.status}\n`;
    if (f.evidence_file) md += `- **Evidence:** [${f.evidence_file}](evidence/${f.evidence_file})\n`;
    if (f.notes) md += `\n${f.notes}\n`;
    md += "\n";
  }
  return md;
}

function credentialsTable(meta: EngagementMetadata): string {
  if (meta.credentials.length === 0) return "*No credentials captured yet.*\n";

  const lines = [
    "| ID | Source | Username | Type | Access | Verified |",
    "|---|---|---|---|---|---|",
  ];
  for (const c of meta.credentials) {
    lines.push(
      `| ${c.id} | ${c.source} | ${c.username} | ${c.cred_type} | ${c.access_level} | ${c.verified ? "Yes" : "No"} |`
    );
  }
  return lines.join("\n") + "\n";
}

function attackPathSection(meta: EngagementMetadata): string {
  if (meta.attack_path.length === 0) return "*No attack path documented yet.*\n";

  return meta.attack_path
    .map((s) => `${s.step}. **${s.description}** *(${s.timestamp})*`)
    .join("\n") + "\n";
}

function reconSummary(meta: EngagementMetadata): string {
  let md = "## Recon Summary\n\n";

  // Live hosts
  md += "### Live Hosts\n\n";
  if (meta.hosts.length === 0) {
    md += "*No hosts discovered yet.*\n\n";
  } else {
    md += "| IP | Hostname | OS | Services | First Seen |\n";
    md += "|---|---|---|---|---|\n";
    for (const h of meta.hosts) {
      const svcSummary = h.services.map((s) => `${s.port}/${s.proto}`).join(", ") || "-";
      md += `| ${h.ip} | ${h.hostname || "-"} | ${h.os || "-"} | ${svcSummary} | ${h.first_seen} |\n`;
    }
    md += "\n";
  }

  // Attack surface map
  md += "### Attack Surface\n\n";
  if (meta.hosts.length === 0) {
    md += "*No attack surface mapped yet.*\n\n";
  } else {
    for (const h of meta.hosts) {
      if (h.services.length === 0) continue;
      md += `**${h.ip}** (${h.hostname || "unknown"}):\n`;
      for (const s of h.services) {
        md += `- ${s.port}/${s.proto} — ${s.service}${s.version ? ` ${s.version}` : ""}${s.notes ? ` (${s.notes})` : ""}\n`;
      }
      md += "\n";
    }
  }

  return md;
}

function evidenceIndex(meta: EngagementMetadata): string {
  if (meta.evidence_index.length === 0) return "*No evidence files yet.*\n";

  const lines = [
    "| Filename | Description | Related Finding | Created |",
    "|---|---|---|---|",
  ];
  for (const e of meta.evidence_index) {
    lines.push(
      `| [${e.filename}](evidence/${e.filename}) | ${e.description} | ${e.related_finding_id || "-"} | ${e.created_at} |`
    );
  }
  return lines.join("\n") + "\n";
}

function deadEndsSection(meta: EngagementMetadata): string {
  if (meta.dead_ends.length === 0) return "*No dead ends recorded.*\n";

  return meta.dead_ends
    .map((d) => `- **${d.technique}** on ${d.target}: ${d.reason} *(${d.timestamp})*`)
    .join("\n") + "\n";
}

function commandLogSection(meta: EngagementMetadata): string {
  if (meta.command_log.length === 0) return "*No commands logged yet.*\n";

  const lines = [
    "| ID | Tool | Command | Target | Exit | Evidence | Time |",
    "|---|---|---|---|---|---|---|",
  ];
  for (const c of meta.command_log) {
    const cmd = c.command.length > 60 ? c.command.slice(0, 57) + "..." : c.command;
    const evidence = c.evidence_file ? `[link](evidence/${c.evidence_file})` : "-";
    lines.push(
      `| ${c.id} | ${c.tool} | \`${cmd}\` | ${c.target} | ${c.exit_code ?? "-"} | ${evidence} | ${c.started_at} |`
    );
  }
  return lines.join("\n") + "\n";
}

function todosSection(meta: EngagementMetadata): string {
  if (meta.todos.length === 0) return "*No TODOs.*\n";

  const pending = meta.todos.filter((t) => t.status === "pending");
  const completed = meta.todos.filter((t) => t.status === "completed");

  let md = "";
  if (pending.length > 0) {
    md += "### Pending\n\n";
    for (const t of pending) {
      md += `- [ ] **${t.id}** [${t.priority}] ${t.description}\n`;
    }
    md += "\n";
  }
  if (completed.length > 0) {
    md += "### Completed\n\n";
    for (const t of completed) {
      md += `- [x] **${t.id}** ${t.description} *(${t.completed_at})*\n`;
    }
    md += "\n";
  }
  return md;
}

export function renderFindings(meta: EngagementMetadata): string {
  let md = `# ${meta.target} — Engagement Report\n\n`;
  md += `**ID:** ${meta.id}  \n`;
  md += `**Status:** ${meta.status}  \n`;
  md += `**Created:** ${meta.created_at}  \n`;
  md += `**Updated:** ${meta.updated_at}  \n\n`;

  // Scope
  md += "## Scope\n\n";
  if (meta.scope.length > 0) {
    for (const s of meta.scope) {
      md += `- ${s}\n`;
    }
  } else {
    md += "*No scope defined.*\n";
  }
  md += "\n";

  if (meta.rules_of_engagement) {
    md += "## Rules of Engagement\n\n";
    md += meta.rules_of_engagement + "\n\n";
  }

  // Executive summary
  md += "## Executive Summary\n\n";
  md += (meta.executive_summary || "*No executive summary yet.*") + "\n\n";

  // Attack path
  md += "## Attack Path\n\n";
  md += attackPathSection(meta) + "\n";

  // Critical/high findings detail
  md += critHighFindings(meta.findings);

  // All findings table
  md += "## All Findings\n\n";
  md += findingsTable(meta.findings) + "\n";

  // Credentials
  md += "## Credentials\n\n";
  md += credentialsTable(meta) + "\n";

  // Recon summary
  md += reconSummary(meta) + "\n";

  // Evidence
  md += "## Evidence Index\n\n";
  md += evidenceIndex(meta) + "\n";

  // Dead ends
  md += "## Dead Ends\n\n";
  md += deadEndsSection(meta) + "\n";

  // Command log
  md += "## Command Log\n\n";
  md += commandLogSection(meta) + "\n";

  // TODOs
  md += "## TODOs\n\n";
  md += todosSection(meta);

  return md;
}
