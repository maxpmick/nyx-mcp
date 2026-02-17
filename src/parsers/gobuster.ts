import type { ToolParser, ParseResult } from "../types.js";

// Parses line-oriented output from gobuster, ffuf, and feroxbuster
// Typical formats:
//   gobuster: /path (Status: 200) [Size: 1234]
//   ffuf:     path [Status: 200, Size: 1234, ...]
//   feroxbuster: 200  GET  1234l  5678w  /path

function parseGobusterOutput(content: string): ParseResult {
  const lines = content.split("\n");
  const entries: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("=")) continue;

    // gobuster style: /path (Status: 200) [Size: 1234]
    const gobusterMatch = trimmed.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
    if (gobusterMatch) {
      entries.push(`| ${gobusterMatch[1]} | ${gobusterMatch[2]} |`);
      continue;
    }

    // feroxbuster style: 200  GET  1234l  5678w  90000c  /path
    const feroxMatch = trimmed.match(/^(\d{3})\s+\w+\s+\S+\s+\S+\s+\S+\s+(\/\S+)/);
    if (feroxMatch) {
      entries.push(`| ${feroxMatch[2]} | ${feroxMatch[1]} |`);
      continue;
    }

    // ffuf style: path [Status: 200, Size: 1234]
    const ffufMatch = trimmed.match(/^(\S+)\s+\[Status:\s*(\d+)/);
    if (ffufMatch) {
      const p = ffufMatch[1].startsWith("/") ? ffufMatch[1] : `/${ffufMatch[1]}`;
      entries.push(`| ${p} | ${ffufMatch[2]} |`);
      continue;
    }
  }

  const raw_text =
    entries.length > 0
      ? "| Path | Status |\n|---|---|\n" + entries.join("\n") + "\n"
      : content;

  return { hosts: [], findings: [], raw_text };
}

export const gobusterParser: ToolParser = {
  name: "gobuster",
  async parse(content: string): Promise<ParseResult> {
    return parseGobusterOutput(content);
  },
};
