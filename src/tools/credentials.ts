import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Credential } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";

const CRED_TYPES = ["password", "hash", "token", "key", "certificate"] as const;

function now(): string {
  return new Date().toISOString();
}

function nextCredId(existing: Credential[]): string {
  let max = 0;
  for (const c of existing) {
    const n = parseInt(c.id.replace("C-", ""), 10);
    if (n > max) max = n;
  }
  return `C-${String(max + 1).padStart(3, "0")}`;
}

export async function addCredential(params: {
  source: string;
  username: string;
  password_or_hash: string;
  cred_type: (typeof CRED_TYPES)[number];
  access_level?: string;
  verified?: boolean;
}): Promise<Credential> {
  const meta = await loadActiveMetadata();
  const id = nextCredId(meta.credentials);

  const cred: Credential = {
    id,
    source: params.source,
    username: params.username,
    password_or_hash: params.password_or_hash,
    cred_type: params.cred_type,
    access_level: params.access_level || "",
    verified: params.verified ?? false,
    created_at: now(),
  };

  meta.credentials.push(cred);
  await saveMetadataAndRender(meta);
  return cred;
}

export function registerCredentialTools(server: McpServer): void {
  server.tool(
    "credential_add",
    "Add a captured credential",
    {
      source: z.string().describe("Where the credential was found"),
      username: z.string().describe("Username"),
      password_or_hash: z.string().describe("Password, hash, token, or key material"),
      cred_type: z.enum(CRED_TYPES).describe("Credential type"),
      access_level: z.string().optional().describe("Access level this credential grants"),
      verified: z.boolean().optional().describe("Whether the credential has been verified working"),
    },
    async (args) => {
      const result = await addCredential(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
