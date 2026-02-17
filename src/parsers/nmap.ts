import { XMLParser } from "fast-xml-parser";
import type { ToolParser, ParseResult, HostData, ServiceData, FindingData } from "../types.js";

function parseNmapXml(content: string): ParseResult {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    isArray: (name) => ["host", "port", "script", "osmatch", "elem", "table"].includes(name),
  });

  const parsed = parser.parse(content);
  const nmaprun = parsed.nmaprun;
  if (!nmaprun) {
    throw new Error("Invalid nmap XML: missing <nmaprun> root element");
  }

  const hosts: HostData[] = [];
  const findings: FindingData[] = [];

  const rawHosts = nmaprun.host || [];
  for (const h of Array.isArray(rawHosts) ? rawHosts : [rawHosts]) {
    // Get IP address
    const addrs = h.address || [];
    const addrList = Array.isArray(addrs) ? addrs : [addrs];
    const ipAddr = addrList.find((a: Record<string, string>) => a["@_addrtype"] === "ipv4" || a["@_addrtype"] === "ipv6");
    if (!ipAddr) continue;

    const ip = ipAddr["@_addr"];

    // Get hostname
    let hostname = "";
    if (h.hostnames?.hostname) {
      const hn = Array.isArray(h.hostnames.hostname) ? h.hostnames.hostname[0] : h.hostnames.hostname;
      hostname = hn?.["@_name"] || "";
    }

    // Get OS
    let os = "";
    if (h.os?.osmatch) {
      const matches = Array.isArray(h.os.osmatch) ? h.os.osmatch : [h.os.osmatch];
      if (matches.length > 0) {
        os = matches[0]["@_name"] || "";
      }
    }

    // Get services
    const services: ServiceData[] = [];
    const ports = h.ports?.port || [];
    const portList = Array.isArray(ports) ? ports : [ports];

    for (const p of portList) {
      const state = p.state?.["@_state"] || "";
      if (state !== "open" && state !== "open|filtered") continue;

      const svc: ServiceData = {
        port: parseInt(p["@_portid"], 10),
        proto: (p["@_protocol"] || "tcp") as "tcp" | "udp",
        service: p.service?.["@_name"] || "unknown",
        version: [p.service?.["@_product"], p.service?.["@_version"]].filter(Boolean).join(" ") || "",
      };
      services.push(svc);

      // Script output → info findings
      const scripts = p.script || [];
      const scriptList = Array.isArray(scripts) ? scripts : [scripts];
      for (const script of scriptList) {
        if (script["@_output"]) {
          findings.push({
            host: ip,
            vulnerability: `nmap-script: ${script["@_id"]}`,
            severity: "info",
            notes: script["@_output"],
            status: "potential",
          });
        }
      }
    }

    hosts.push({ ip, hostname, os, services });
  }

  return { hosts, findings };
}

export const nmapParser: ToolParser = {
  name: "nmap",
  async parse(content: string): Promise<ParseResult> {
    return parseNmapXml(content);
  },
};
