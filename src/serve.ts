import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerEngagementTools } from "./tools/engagement.js";
import { registerFindingTools } from "./tools/findings.js";
import { registerHostTools } from "./tools/hosts.js";
import { registerCredentialTools } from "./tools/credentials.js";
import { registerEvidenceTools } from "./tools/evidence.js";
import { registerNarrativeTools } from "./tools/narrative.js";
import { registerTrackingTools } from "./tools/tracking.js";
import { registerReadingTools } from "./tools/reading.js";
import { registerCommandLogTools } from "./tools/commandLog.js";
import { registerIngestTools } from "./tools/ingest.js";

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: "nyx-memory",
    version: "1.0.0",
  });

  registerEngagementTools(server);
  registerFindingTools(server);
  registerHostTools(server);
  registerCredentialTools(server);
  registerEvidenceTools(server);
  registerNarrativeTools(server);
  registerTrackingTools(server);
  registerReadingTools(server);
  registerCommandLogTools(server);
  registerIngestTools(server);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
