import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Host, Service } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";
import { getEngagementDir, writeFileAtomic } from "../storage/index.js";
import { renderHost } from "../render/host.js";

function now(): string {
  return new Date().toISOString();
}

const HOST_SECTIONS = [
  "enumeration",
  "vulnerabilities",
  "exploitation",
  "post_exploitation",
  "credentials",
  "key_commands",
] as const;

type HostSection = (typeof HOST_SECTIONS)[number];

function mergeServices(existing: Service[], incoming: Service[]): Service[] {
  const merged = [...existing];
  for (const svc of incoming) {
    const match = merged.find((s) => s.port === svc.port && s.proto === svc.proto);
    if (match) {
      if (svc.service) match.service = svc.service;
      if (svc.version) match.version = svc.version;
      if (svc.notes) match.notes = svc.notes;
    } else {
      merged.push({ ...svc });
    }
  }
  return merged;
}

export async function discoverHost(params: {
  ip: string;
  hostname?: string;
  os?: string;
  services?: { port: number; proto: "tcp" | "udp"; service?: string; version?: string; notes?: string }[];
}): Promise<Host> {
  const meta = await loadActiveMetadata();
  let host = meta.hosts.find((h) => h.ip === params.ip);

  if (host) {
    // Merge additively
    if (params.hostname && !host.hostname) host.hostname = params.hostname;
    if (params.os && !host.os) host.os = params.os;
    if (params.services) {
      const incoming: Service[] = params.services.map((s) => ({
        port: s.port,
        proto: s.proto,
        service: s.service || "unknown",
        version: s.version || "",
        notes: s.notes || "",
      }));
      host.services = mergeServices(host.services, incoming);
    }
    host.updated_at = now();
  } else {
    // Create new
    host = {
      ip: params.ip,
      hostname: params.hostname || "",
      os: params.os || "",
      first_seen: now(),
      updated_at: now(),
      services: (params.services || []).map((s) => ({
        port: s.port,
        proto: s.proto,
        service: s.service || "unknown",
        version: s.version || "",
        notes: s.notes || "",
      })),
      enumeration: "",
      vulnerabilities: "",
      exploitation: "",
      post_exploitation: "",
      credentials: "",
      key_commands: "",
    };
    meta.hosts.push(host);
  }

  await saveMetadataAndRender(meta);

  // Render host file
  const engDir = getEngagementDir(meta.id);
  await writeFileAtomic(path.join(engDir, "hosts", `${host.ip}.md`), renderHost(host));

  return host;
}

export async function updateHost(params: {
  ip: string;
  section: HostSection;
  content: string;
}): Promise<Host> {
  const meta = await loadActiveMetadata();
  const host = meta.hosts.find((h) => h.ip === params.ip);
  if (!host) {
    throw Object.assign(new Error(`Host '${params.ip}' not found. Use host_discover first.`), {
      code: "host_not_found",
    });
  }

  // Append to section
  const current = host[params.section];
  host[params.section] = current ? `${current}\n\n${params.content}` : params.content;
  host.updated_at = now();

  await saveMetadataAndRender(meta);

  const engDir = getEngagementDir(meta.id);
  await writeFileAtomic(path.join(engDir, "hosts", `${host.ip}.md`), renderHost(host));

  return host;
}

export function registerHostTools(server: McpServer): void {
  server.tool(
    "host_discover",
    "Discover or update a host with services (additive merge)",
    {
      ip: z.string().describe("Host IP address"),
      hostname: z.string().optional().describe("Hostname"),
      os: z.string().optional().describe("Operating system"),
      services: z
        .array(
          z.object({
            port: z.number().describe("Port number"),
            proto: z.enum(["tcp", "udp"]).describe("Protocol"),
            service: z.string().optional().describe("Service name"),
            version: z.string().optional().describe("Version string"),
            notes: z.string().optional().describe("Notes"),
          })
        )
        .optional()
        .describe("Discovered services"),
    },
    async (args) => {
      const result = await discoverHost(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "host_update",
    "Append content to a host section (enumeration, vulnerabilities, etc.)",
    {
      ip: z.string().describe("Host IP address"),
      section: z.enum(HOST_SECTIONS).describe("Section to update"),
      content: z.string().describe("Content to append"),
    },
    async (args) => {
      const result = await updateHost(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
