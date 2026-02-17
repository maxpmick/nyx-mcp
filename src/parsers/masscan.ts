import { XMLParser } from "fast-xml-parser";
import type { ToolParser, ParseResult, HostData, ServiceData } from "../types.js";

function parseMasscanXml(content: string): ParseResult {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    isArray: (name) => ["host", "port", "address"].includes(name),
  });

  const parsed = parser.parse(content);
  const nmaprun = parsed.nmaprun;
  if (!nmaprun) throw new Error("Invalid masscan XML");

  const hostMap = new Map<string, HostData>();

  const rawHosts = nmaprun.host || [];
  for (const h of Array.isArray(rawHosts) ? rawHosts : [rawHosts]) {
    const addrs = h.address || [];
    const addrList = Array.isArray(addrs) ? addrs : [addrs];
    const ipAddr = addrList.find((a: Record<string, string>) => a["@_addrtype"] === "ipv4" || a["@_addrtype"] === "ipv6");
    if (!ipAddr) continue;

    const ip = ipAddr["@_addr"];
    if (!hostMap.has(ip)) {
      hostMap.set(ip, { ip, services: [] });
    }
    const host = hostMap.get(ip)!;

    const ports = h.ports?.port || [];
    const portList = Array.isArray(ports) ? ports : [ports];
    for (const p of portList) {
      const state = p.state?.["@_state"] || "";
      if (state !== "open") continue;

      const svc: ServiceData = {
        port: parseInt(p["@_portid"], 10),
        proto: (p["@_protocol"] || "tcp") as "tcp" | "udp",
        service: "unknown",
        version: "",
      };
      host.services!.push(svc);
    }
  }

  return { hosts: Array.from(hostMap.values()), findings: [] };
}

function parseMasscanJson(content: string): ParseResult {
  // Masscan JSON is an array of records (with trailing comma issues)
  const cleaned = content.replace(/,\s*\]/, "]").replace(/,\s*$/, "");
  let records: Array<{ ip: string; ports: Array<{ port: number; proto: string; status: string }> }>;
  try {
    records = JSON.parse(cleaned);
  } catch {
    throw new Error("Invalid masscan JSON output");
  }

  const hostMap = new Map<string, HostData>();

  for (const rec of records) {
    if (!rec.ip) continue;
    if (!hostMap.has(rec.ip)) {
      hostMap.set(rec.ip, { ip: rec.ip, services: [] });
    }
    const host = hostMap.get(rec.ip)!;

    for (const p of rec.ports || []) {
      if (p.status !== "open") continue;
      host.services!.push({
        port: p.port,
        proto: (p.proto || "tcp") as "tcp" | "udp",
        service: "unknown",
        version: "",
      });
    }
  }

  return { hosts: Array.from(hostMap.values()), findings: [] };
}

export const masscanParser: ToolParser = {
  name: "masscan",
  async parse(content: string): Promise<ParseResult> {
    const trimmed = content.trim();
    if (trimmed.startsWith("<") || trimmed.startsWith("<?xml")) {
      return parseMasscanXml(content);
    }
    return parseMasscanJson(content);
  },
};
