import type { Host } from "../types.js";

function servicesTable(host: Host): string {
  if (host.services.length === 0) return "*No services discovered yet.*\n";

  const lines = [
    "| Port | Proto | Service | Version | Notes |",
    "|---|---|---|---|---|",
  ];
  for (const s of host.services) {
    lines.push(`| ${s.port} | ${s.proto} | ${s.service} | ${s.version || "-"} | ${s.notes || "-"} |`);
  }
  return lines.join("\n") + "\n";
}

function section(title: string, content: string): string {
  let md = `## ${title}\n\n`;
  md += (content.trim() || "*Nothing recorded yet.*") + "\n\n";
  return md;
}

export function renderHost(host: Host): string {
  let md = `# ${host.ip}`;
  if (host.hostname) md += ` (${host.hostname})`;
  md += "\n\n";

  if (host.os) md += `**OS:** ${host.os}  \n`;
  md += `**First Seen:** ${host.first_seen}  \n`;
  md += `**Updated:** ${host.updated_at}  \n\n`;

  md += "## Services\n\n";
  md += servicesTable(host) + "\n";

  md += section("Enumeration", host.enumeration);
  md += section("Vulnerabilities", host.vulnerabilities);
  md += section("Exploitation", host.exploitation);
  md += section("Post-Exploitation", host.post_exploitation);
  md += section("Credentials", host.credentials);
  md += section("Key Commands", host.key_commands);

  return md;
}
