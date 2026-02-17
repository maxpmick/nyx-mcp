import { XMLParser } from "fast-xml-parser";
import type { ToolParser, ParseResult, FindingData } from "../types.js";

function parseNiktoXml(content: string): ParseResult {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    isArray: (name) => ["item", "scandetails"].includes(name),
  });

  const parsed = parser.parse(content);
  const findings: FindingData[] = [];
  let host = "";

  const niktoscan = parsed.niktoscan;
  if (!niktoscan) throw new Error("Invalid nikto XML");

  const scanDetails = niktoscan.scandetails || [];
  for (const scan of Array.isArray(scanDetails) ? scanDetails : [scanDetails]) {
    host = scan["@_targetip"] || scan["@_targethostname"] || "";
    const items = scan.item || [];
    for (const item of Array.isArray(items) ? items : [items]) {
      const desc = item.description || item["@_description"] || "";
      const uri = item.uri || item["@_uri"] || "";
      findings.push({
        host,
        vulnerability: `nikto: ${desc.slice(0, 120)}`,
        severity: "info",
        status: "potential",
        notes: uri ? `URI: ${uri}\n${desc}` : desc,
      });
    }
  }

  return { hosts: host ? [{ ip: host }] : [], findings };
}

function parseNiktoStdout(content: string): ParseResult {
  const findings: FindingData[] = [];
  let host = "";
  const lines = content.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // Target IP line
    const targetMatch = trimmed.match(/\+\s*Target IP:\s*(\S+)/);
    if (targetMatch) {
      host = targetMatch[1];
      continue;
    }

    // Finding lines start with + and contain OSVDB or description
    if (trimmed.startsWith("+") && !trimmed.startsWith("+ Target") && !trimmed.startsWith("+ Start") && !trimmed.startsWith("+ End")) {
      const desc = trimmed.replace(/^\+\s*/, "");
      if (desc.length > 10) {
        // Determine severity from content
        const sev: FindingData["severity"] = desc.toLowerCase().includes("vulnerability") ? "low" : "info";
        findings.push({
          host: host || "unknown",
          vulnerability: `nikto: ${desc.slice(0, 120)}`,
          severity: sev,
          status: "potential",
          notes: desc,
        });
      }
    }
  }

  return { hosts: host ? [{ ip: host }] : [], findings };
}

export const niktoParser: ToolParser = {
  name: "nikto",
  async parse(content: string): Promise<ParseResult> {
    const trimmed = content.trim();
    if (trimmed.startsWith("<") || trimmed.startsWith("<?xml")) {
      return parseNiktoXml(content);
    }
    return parseNiktoStdout(content);
  },
};
