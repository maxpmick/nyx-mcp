import { describe, it, before, after } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

// Set data dir before importing modules
const TEST_DIR = path.join(os.tmpdir(), `nyx-test-${Date.now()}`);
process.env.NYX_DATA_DIR = TEST_DIR;

import { createEngagement, listEngagements, resumeEngagement, engagementStatus, closeEngagement, loadActiveMetadata } from "../tools/engagement.js";
import { discoverHost, updateHost } from "../tools/hosts.js";
import { addFinding, updateFinding } from "../tools/findings.js";
import { addCredential } from "../tools/credentials.js";
import { saveEvidence } from "../tools/evidence.js";
import { updateAttackPath, updateExecutiveSummary } from "../tools/narrative.js";
import { logDeadEnd, addTodo, completeTodo } from "../tools/tracking.js";
import { logCommand } from "../tools/commandLog.js";
import { readNotes } from "../tools/reading.js";
import { getActiveEngagementId, getIndex } from "../storage/index.js";
import { nmapParser } from "../parsers/nmap.js";
import { masscanParser } from "../parsers/masscan.js";
import { gobusterParser } from "../parsers/gobuster.js";
import { niktoParser } from "../parsers/nikto.js";
import { ingestToolOutput } from "../tools/ingest.js";
import { createMcpServer } from "../serve.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

describe("nyx-memory integration", () => {
  let engagementId: string;

  after(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  // ── Engagement lifecycle ──

  it("creates an engagement", async () => {
    const meta = await createEngagement({
      target: "Test Corp",
      scope: ["10.0.0.0/24", "192.168.1.0/24"],
      rules_of_engagement: "No DoS. Business hours only.",
    });

    assert.ok(meta.id.includes("test-corp"));
    assert.equal(meta.target, "Test Corp");
    assert.equal(meta.scope.length, 2);
    assert.equal(meta.status, "active");
    assert.equal(meta.schema_version, 1);
    engagementId = meta.id;
  });

  it("sets the active engagement", async () => {
    const id = await getActiveEngagementId();
    assert.equal(id, engagementId);
  });

  it("lists engagements with current marker", async () => {
    const list = await listEngagements();
    assert.equal(list.length, 1);
    assert.equal(list[0].is_current, true);
    assert.equal(list[0].target, "Test Corp");
  });

  it("handles engagement ID collisions", async () => {
    const meta2 = await createEngagement({
      target: "Test Corp",
      scope: ["172.16.0.0/16"],
    });
    assert.ok(meta2.id.endsWith("-2"), `Expected collision suffix, got ${meta2.id}`);

    // Resume original
    await resumeEngagement(engagementId);
  });

  it("reports engagement status", async () => {
    const status = await engagementStatus();
    assert.equal(status.target, "Test Corp");
    assert.equal(status.host_count, 0);
  });

  // ── Host discovery ──

  it("discovers a new host", async () => {
    const host = await discoverHost({
      ip: "10.0.0.1",
      hostname: "gateway.test.corp",
      os: "Linux 5.x",
      services: [
        { port: 22, proto: "tcp", service: "ssh", version: "OpenSSH 8.9" },
        { port: 80, proto: "tcp", service: "http", version: "nginx 1.24" },
      ],
    });

    assert.equal(host.ip, "10.0.0.1");
    assert.equal(host.hostname, "gateway.test.corp");
    assert.equal(host.services.length, 2);
  });

  it("merges services additively on re-discover", async () => {
    const host = await discoverHost({
      ip: "10.0.0.1",
      services: [
        { port: 443, proto: "tcp", service: "https", version: "nginx 1.24" },
        { port: 22, proto: "tcp", version: "OpenSSH 9.0" }, // Update existing
      ],
    });

    assert.equal(host.services.length, 3);
    const ssh = host.services.find((s) => s.port === 22);
    assert.equal(ssh?.version, "OpenSSH 9.0"); // Updated
    assert.equal(host.hostname, "gateway.test.corp"); // Not cleared
  });

  it("updates a host section", async () => {
    const host = await updateHost({
      ip: "10.0.0.1",
      section: "enumeration",
      content: "### Web directories\n\n- /admin (403)\n- /api (200)",
    });

    assert.ok(host.enumeration.includes("/admin"));
  });

  it("appends to host section", async () => {
    const host = await updateHost({
      ip: "10.0.0.1",
      section: "enumeration",
      content: "### Subdomains\n\n- api.test.corp",
    });

    assert.ok(host.enumeration.includes("/admin")); // Original content preserved
    assert.ok(host.enumeration.includes("api.test.corp")); // New content appended
  });

  it("rejects updates to non-existent hosts", async () => {
    await assert.rejects(
      () => updateHost({ ip: "99.99.99.99", section: "enumeration", content: "test" }),
      (err: Error & { code?: string }) => err.code === "host_not_found"
    );
  });

  // ── Findings ──

  it("adds a finding", async () => {
    const finding = await addFinding({
      host: "10.0.0.1",
      vulnerability: "SQL Injection in /api/users",
      severity: "critical",
      cvss: 9.8,
      notes: "Parameter: id, Payload: ' OR 1=1--",
    });

    assert.equal(finding.id, "F-001");
    assert.equal(finding.severity, "critical");
    assert.equal(finding.cvss, 9.8);
  });

  it("auto-increments finding IDs", async () => {
    const finding = await addFinding({
      host: "10.0.0.1",
      vulnerability: "Directory traversal in /api/files",
      severity: "high",
      cvss: 7.5,
    });

    assert.equal(finding.id, "F-002");
  });

  it("updates a finding with appended notes", async () => {
    const updated = await updateFinding({
      id: "F-001",
      status: "exploited",
      notes: "Successfully dumped database",
    });

    assert.equal(updated.status, "exploited");
    assert.ok(updated.notes.includes("OR 1=1")); // Original
    assert.ok(updated.notes.includes("dumped database")); // Appended
  });

  it("rejects invalid CVSS", async () => {
    await assert.rejects(
      () => addFinding({ host: "10.0.0.1", vulnerability: "test", severity: "low", cvss: 15 }),
      (err: Error & { code?: string }) => err.code === "invalid_cvss"
    );
  });

  it("rejects updates to non-existent findings", async () => {
    await assert.rejects(
      () => updateFinding({ id: "F-999", notes: "test" }),
      (err: Error & { code?: string }) => err.code === "finding_not_found"
    );
  });

  // ── Credentials ──

  it("adds a credential", async () => {
    const cred = await addCredential({
      source: "10.0.0.1 MySQL dump",
      username: "admin",
      password_or_hash: "password123",
      cred_type: "password",
      access_level: "admin",
      verified: true,
    });

    assert.equal(cred.id, "C-001");
    assert.equal(cred.verified, true);
  });

  // ── Evidence ──

  it("saves evidence", async () => {
    const result = await saveEvidence({
      filename: "sqli-proof.txt",
      content: "SQL injection dump contents...",
      description: "SQLi proof of concept output",
      related_finding_id: "F-001",
    });

    assert.equal(result.overwritten, false);
    assert.equal(result.entry.related_finding_id, "F-001");
  });

  it("warns on overwrite", async () => {
    const result = await saveEvidence({
      filename: "sqli-proof.txt",
      content: "Updated content",
    });

    assert.equal(result.overwritten, true);
  });

  it("rejects filenames with path separators", async () => {
    await assert.rejects(
      () => saveEvidence({ filename: "../evil.txt", content: "test" }),
      (err: Error & { code?: string }) => err.code === "invalid_filename"
    );
  });

  // ── Narrative ──

  it("adds attack path steps", async () => {
    const step1 = await updateAttackPath({ description: "Initial nmap scan discovered web server on 10.0.0.1" });
    assert.equal(step1.step, 1);

    const step2 = await updateAttackPath({ description: "Discovered SQLi in /api/users endpoint" });
    assert.equal(step2.step, 2);
  });

  it("updates executive summary", async () => {
    const result = await updateExecutiveSummary({
      summary: "Critical SQL injection found allowing full database access.",
    });
    assert.ok(result.summary.includes("Critical SQL injection"));
  });

  // ── Tracking ──

  it("logs a dead end", async () => {
    const de = await logDeadEnd({
      technique: "Default credentials",
      target: "10.0.0.1 SSH",
      reason: "No default creds work, key-based auth only",
    });
    assert.ok(de.timestamp);
  });

  it("adds and completes a TODO", async () => {
    const todo = await addTodo({
      description: "Try lateral movement to 10.0.0.2",
      priority: "high",
    });
    assert.equal(todo.id, "T-001");
    assert.equal(todo.status, "pending");

    const completed = await completeTodo({ id: "T-001" });
    assert.equal(completed.status, "completed");
    assert.ok(completed.completed_at);
  });

  it("rejects completion of non-existent TODO", async () => {
    await assert.rejects(
      () => completeTodo({ id: "T-999" }),
      (err: Error & { code?: string }) => err.code === "todo_not_found"
    );
  });

  // ── Command log ──

  it("logs a command", async () => {
    const entry = await logCommand({
      command: "nmap -sV -p- 10.0.0.1",
      target: "10.0.0.1",
      exit_code: 0,
      source: "nyx-log",
    });

    assert.equal(entry.id, "CMD-001");
    assert.equal(entry.tool, "nmap"); // Auto-detected
  });

  // ── Reading ──

  it("reads findings as markdown", async () => {
    const md = await readNotes({ what: "findings" });
    assert.ok(md.includes("SQL Injection"));
    assert.ok(md.includes("F-001"));
  });

  it("reads a specific host", async () => {
    const md = await readNotes({ what: "host", host_ip: "10.0.0.1" });
    assert.ok(md.includes("10.0.0.1"));
    assert.ok(md.includes("OpenSSH"));
  });

  it("searches across engagement data", async () => {
    const result = await readNotes({ what: "search", query: "SQL" });
    assert.ok(result.includes("F-001"));
  });

  it("reads TODOs grouped by status", async () => {
    const result = await readNotes({ what: "todos" });
    assert.ok(result.includes("Completed"));
  });

  it("reads attack path", async () => {
    const result = await readNotes({ what: "attack_path" });
    assert.ok(result.includes("nmap scan"));
  });

  it("reads credentials", async () => {
    const result = await readNotes({ what: "credentials" });
    assert.ok(result.includes("admin"));
  });

  it("reads command log", async () => {
    const result = await readNotes({ what: "command_log" });
    assert.ok(result.includes("CMD-001"));
  });

  // ── Rendered files on disk ──

  it("writes FINDINGS.md to disk", async () => {
    const engDir = path.join(TEST_DIR, engagementId);
    const content = await fs.readFile(path.join(engDir, "FINDINGS.md"), "utf-8");
    assert.ok(content.includes("Test Corp"));
    assert.ok(content.includes("SQL Injection"));
    assert.ok(content.includes("10.0.0.1"));
  });

  it("writes host markdown to disk", async () => {
    const engDir = path.join(TEST_DIR, engagementId);
    const content = await fs.readFile(path.join(engDir, "hosts", "10.0.0.1.md"), "utf-8");
    assert.ok(content.includes("gateway.test.corp"));
    assert.ok(content.includes("22"));
  });

  // ── Index ──

  it("maintains index.json with counts", async () => {
    const index = await getIndex();
    const entry = index.find((e) => e.id === engagementId);
    assert.ok(entry);
    assert.equal(entry!.finding_count, 2);
    assert.equal(entry!.host_count, 1);
    assert.equal(entry!.credential_count, 1);
    assert.equal(entry!.command_count, 1);
  });

  // ── Close engagement ──

  it("closes the engagement", async () => {
    const result = await closeEngagement({
      status: "completed",
      executive_summary: "Final: Critical SQLi found. Full DB access achieved.",
    });

    assert.equal(result.status, "completed");

    const activeId = await getActiveEngagementId();
    assert.equal(activeId, null);
  });

  it("rejects operations without active engagement", async () => {
    await assert.rejects(
      () => engagementStatus(),
      (err: Error & { code?: string }) => err.code === "no_active_engagement"
    );
  });

  // ── Resume ──

  it("resumes an engagement", async () => {
    const result = await resumeEngagement(engagementId);
    assert.equal(result.metadata.target, "Test Corp");
    assert.equal(result.open_todos, 0); // We completed the only one

    const activeId = await getActiveEngagementId();
    assert.equal(activeId, engagementId);
  });

  it("rejects resuming non-existent engagement", async () => {
    await assert.rejects(
      () => resumeEngagement("non-existent-id"),
      (err: Error & { code?: string }) => err.code === "engagement_not_found"
    );
  });

  // ── Ingest pipeline ──

  it("ingests nmap XML end-to-end", async () => {
    const nmapXml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.99" addrtype="ipv4"/>
    <hostnames><hostname name="ingest-test.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="Squid" version="5.2"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

    // Write fixture to a temp file
    const fixturePath = path.join(TEST_DIR, "nmap-fixture.xml");
    await fs.writeFile(fixturePath, nmapXml, "utf-8");

    const result = await ingestToolOutput({ tool: "nmap", file: fixturePath });
    assert.equal(result.hosts_discovered, 1);
    assert.equal(result.services_added, 1);
    assert.equal(result.findings_added, 0);
    assert.equal(result.evidence_saved, true);

    // Verify host was actually created in the engagement
    const hostMd = await readNotes({ what: "host", host_ip: "10.0.0.99" });
    assert.ok(hostMd.includes("10.0.0.99"));
    assert.ok(hostMd.includes("8080"));
    assert.ok(hostMd.includes("Squid"));
  });

  it("ingests nikto XML with findings", async () => {
    const niktoXml = `<?xml version="1.0" ?>
<niktoscan>
  <scandetails targetip="10.0.0.99" targetport="8080">
    <item id="1" method="GET">
      <description>Server leaks inodes via ETags</description>
      <uri>/</uri>
    </item>
  </scandetails>
</niktoscan>`;

    const fixturePath = path.join(TEST_DIR, "nikto-fixture.xml");
    await fs.writeFile(fixturePath, niktoXml, "utf-8");

    const result = await ingestToolOutput({ tool: "nikto", file: fixturePath, target: "10.0.0.99" });
    assert.equal(result.hosts_discovered, 1);
    assert.equal(result.findings_added, 1);
    assert.equal(result.evidence_saved, true);
  });

  it("rejects ingest of unsupported tool", async () => {
    await assert.rejects(
      () => ingestToolOutput({ tool: "burpsuite", file: "/tmp/fake.xml" }),
      (err: Error & { code?: string }) => err.code === "unsupported_tool"
    );
  });

  it("rejects ingest of missing file", async () => {
    await assert.rejects(
      () => ingestToolOutput({ tool: "nmap", file: "/tmp/nonexistent-file-xyz.xml" }),
      (err: Error & { code?: string }) => err.code === "file_not_found"
    );
  });
});

// ── Parser unit tests ──

describe("parsers", () => {
  it("parses nmap XML", async () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.4" accuracy="95"/></os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.52"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

    const result = await nmapParser.parse(xml);
    assert.equal(result.hosts.length, 1);
    assert.equal(result.hosts[0].ip, "192.168.1.1");
    assert.equal(result.hosts[0].hostname, "router.local");
    assert.equal(result.hosts[0].os, "Linux 5.4");
    assert.equal(result.hosts[0].services!.length, 2); // Closed port excluded
    assert.equal(result.hosts[0].services![0].port, 22);
    assert.equal(result.hosts[0].services![0].version, "OpenSSH 8.9");
  });

  it("parses masscan JSON", async () => {
    const json = `[
      {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
      {"ip": "10.0.0.2", "ports": [{"port": 22, "proto": "tcp", "status": "open"}, {"port": 443, "proto": "tcp", "status": "open"}]}
    ]`;

    const result = await masscanParser.parse(json);
    assert.equal(result.hosts.length, 2);
    assert.equal(result.hosts[0].services!.length, 1);
    assert.equal(result.hosts[1].services!.length, 2);
    // Masscan doesn't fingerprint
    assert.equal(result.hosts[0].services![0].service, "unknown");
  });

  it("parses gobuster output", async () => {
    const output = `/admin (Status: 403) [Size: 162]
/api (Status: 200) [Size: 4521]
/login (Status: 200) [Size: 1823]
# comment line
`;

    const result = await gobusterParser.parse(output);
    assert.ok(result.raw_text);
    assert.ok(result.raw_text!.includes("/admin"));
    assert.ok(result.raw_text!.includes("403"));
  });

  // ── Nikto parser ──

  it("parses nikto XML", async () => {
    const xml = `<?xml version="1.0" ?>
<niktoscan>
  <scandetails targetip="10.0.0.5" targethostname="web.test.corp" targetport="80">
    <item id="1" method="GET">
      <description>Server leaks inodes via ETags</description>
      <uri>/</uri>
    </item>
    <item id="2" method="GET">
      <description>The X-Content-Type-Options header is not set</description>
      <uri>/index.html</uri>
    </item>
  </scandetails>
</niktoscan>`;

    const result = await niktoParser.parse(xml);
    assert.equal(result.hosts.length, 1);
    assert.equal(result.hosts[0].ip, "10.0.0.5");
    assert.equal(result.findings.length, 2);
    assert.equal(result.findings[0].severity, "info");
    assert.ok(result.findings[0].vulnerability.startsWith("nikto:"));
    assert.ok(result.findings[0].notes!.includes("URI: /"));
    assert.ok(result.findings[1].notes!.includes("/index.html"));
  });

  it("parses nikto stdout", async () => {
    const stdout = `- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.0.5
+ Target Hostname:    web.test.corp
+ Target Port:        80
+ Start Time:         2025-01-15 10:30:00 (GMT)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52
+ /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS vulnerability.
+ End Time:           2025-01-15 10:31:00 (GMT)
---------------------------------------------------------------------------`;

    const result = await niktoParser.parse(stdout);
    assert.equal(result.hosts.length, 1);
    assert.equal(result.hosts[0].ip, "10.0.0.5");
    assert.ok(result.findings.length >= 2);
    assert.equal(result.findings[0].severity, "info");
    assert.equal(result.findings[0].status, "potential");
    assert.ok(result.findings[0].vulnerability.startsWith("nikto:"));
  });
});

// ── MCP server protocol tests ──

describe("MCP server", () => {
  let client: Client;
  let serverTransport: InMemoryTransport;
  let clientTransport: InMemoryTransport;

  // Helper to call a tool and parse the JSON text response
  async function call(name: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const result = await client.callTool({ name, arguments: args });
    const content = result.content as Array<{ type: string; text: string }>;
    assert.ok(content.length > 0, `Tool ${name} returned no content`);
    assert.equal(content[0].type, "text");
    return JSON.parse(content[0].text);
  }

  before(async () => {
    const server = createMcpServer();
    [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);

    client = new Client({ name: "test-client", version: "1.0.0" });
    await client.connect(clientTransport);
  });

  after(async () => {
    await clientTransport.close();
    await serverTransport.close();
  });

  // ── Server initialization ──

  it("reports server info on connect", () => {
    const info = client.getServerVersion();
    assert.ok(info);
    assert.equal(info!.name, "nyx-memory");
    assert.equal(info!.version, "1.0.0");
  });

  it("lists all 19 tools", async () => {
    const result = await client.listTools();
    const names = result.tools.map((t) => t.name).sort();
    assert.equal(names.length, 19);

    const expected = [
      "attack_path_update",
      "command_log",
      "credential_add",
      "dead_end_log",
      "engagement_close",
      "engagement_create",
      "engagement_list",
      "engagement_resume",
      "engagement_status",
      "evidence_save",
      "executive_summary_update",
      "finding_add",
      "finding_update",
      "host_discover",
      "host_update",
      "ingest_tool_output",
      "notes_read",
      "todo_add",
      "todo_complete",
    ];
    assert.deepEqual(names, expected);
  });

  it("each tool has a description and input schema", async () => {
    const result = await client.listTools();
    for (const tool of result.tools) {
      assert.ok(tool.description, `${tool.name} missing description`);
      assert.ok(tool.inputSchema, `${tool.name} missing inputSchema`);
      assert.equal(tool.inputSchema.type, "object");
    }
  });

  // ── Full engagement lifecycle over MCP protocol ──

  it("creates an engagement via MCP", async () => {
    const data = await call("engagement_create", {
      target: "MCP Test Corp",
      scope: ["10.10.0.0/24"],
      rules_of_engagement: "Test only",
    });
    assert.ok((data as { id: string }).id);
    assert.equal(data.target, "MCP Test Corp");
    assert.equal(data.status, "active");
  });

  it("lists engagements via MCP", async () => {
    const data = await call("engagement_list");
    const entries = data as unknown as Array<{ target: string; is_current: boolean }>;
    assert.ok(entries.length >= 1);
    const mcpEntry = entries.find((e) => e.target === "MCP Test Corp");
    assert.ok(mcpEntry);
    assert.equal(mcpEntry!.is_current, true);
  });

  it("gets engagement status via MCP", async () => {
    const data = await call("engagement_status");
    assert.equal(data.target, "MCP Test Corp");
    assert.equal(data.host_count, 0);
  });

  it("discovers a host via MCP", async () => {
    const data = await call("host_discover", {
      ip: "10.10.0.1",
      hostname: "mcp-host.local",
      os: "Ubuntu 22.04",
      services: [
        { port: 22, proto: "tcp", service: "ssh", version: "OpenSSH 9.1" },
        { port: 80, proto: "tcp", service: "http", version: "Apache 2.4" },
      ],
    });
    assert.equal(data.ip, "10.10.0.1");
    assert.equal(data.hostname, "mcp-host.local");
    const services = data.services as Array<{ port: number }>;
    assert.equal(services.length, 2);
  });

  it("updates a host section via MCP", async () => {
    const data = await call("host_update", {
      ip: "10.10.0.1",
      section: "enumeration",
      content: "### Gobuster\n\n- /admin (403)\n- /api (200)",
    });
    assert.ok((data as { enumeration: string }).enumeration.includes("/admin"));
  });

  it("adds a finding via MCP", async () => {
    const data = await call("finding_add", {
      host: "10.10.0.1",
      vulnerability: "RCE via deserialization",
      severity: "critical",
      cvss: 9.8,
      notes: "Java deserialization in /api/import",
    });
    assert.ok((data as { id: string }).id);
    assert.equal(data.severity, "critical");
  });

  it("updates a finding via MCP", async () => {
    const data = await call("finding_update", {
      id: "F-001",
      status: "exploited",
      notes: "Got reverse shell",
    });
    assert.equal(data.status, "exploited");
    assert.ok((data as { notes: string }).notes.includes("reverse shell"));
  });

  it("returns isError for invalid finding update", async () => {
    const result = await client.callTool({
      name: "finding_update",
      arguments: { id: "F-999", notes: "nope" },
    });
    assert.equal(result.isError, true);
  });

  it("adds a credential via MCP", async () => {
    const data = await call("credential_add", {
      source: "10.10.0.1 /etc/shadow",
      username: "root",
      password_or_hash: "$6$rounds=...",
      cred_type: "hash",
      access_level: "root",
      verified: false,
    });
    assert.ok((data as { id: string }).id);
    assert.equal(data.username, "root");
  });

  it("saves evidence via MCP", async () => {
    const data = await call("evidence_save", {
      filename: "rce-proof.txt",
      content: "uid=0(root) gid=0(root)",
      description: "RCE proof",
    });
    assert.equal(data.overwritten, false);
  });

  it("logs a command via MCP", async () => {
    const data = await call("command_log", {
      command: "nmap -sV 10.10.0.1",
      target: "10.10.0.1",
      exit_code: 0,
      source: "mcp",
    });
    assert.ok((data as { id: string }).id);
    assert.equal(data.tool, "nmap");
  });

  it("updates attack path via MCP", async () => {
    const data = await call("attack_path_update", {
      description: "Discovered deserialization RCE on 10.10.0.1",
    });
    assert.equal(data.step, 1);
  });

  it("updates executive summary via MCP", async () => {
    const data = await call("executive_summary_update", {
      summary: "Critical RCE found on primary web server.",
    });
    assert.ok((data as { summary: string }).summary.includes("Critical RCE"));
  });

  it("logs a dead end via MCP", async () => {
    const data = await call("dead_end_log", {
      technique: "Brute force SSH",
      target: "10.10.0.1",
      reason: "Fail2ban active, rate-limited",
    });
    assert.ok(data.timestamp);
  });

  it("adds and completes a TODO via MCP", async () => {
    const todo = await call("todo_add", {
      description: "Pivot to 10.10.0.2",
      priority: "high",
    });
    assert.ok((todo as { id: string }).id);
    assert.equal(todo.status, "pending");

    const done = await call("todo_complete", { id: (todo as { id: string }).id });
    assert.equal(done.status, "completed");
  });

  // ── Reading via MCP ──

  it("reads findings via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "findings" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("RCE via deserialization"));
  });

  it("reads a host via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "host", host_ip: "10.10.0.1" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("10.10.0.1"));
    assert.ok(text.includes("OpenSSH"));
  });

  it("searches via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "search", query: "deserialization" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("F-001"));
  });

  it("reads credentials via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "credentials" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("root"));
  });

  it("reads attack path via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "attack_path" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("deserialization"));
  });

  it("reads command log via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "command_log" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("nmap"));
  });

  it("reads TODOs via MCP", async () => {
    const result = await client.callTool({
      name: "notes_read",
      arguments: { what: "todos" },
    });
    const text = (result.content as Array<{ text: string }>)[0].text;
    assert.ok(text.includes("Pivot"));
  });

  // ── Ingest via MCP ──

  it("ingests nmap output via MCP", async () => {
    const nmapXml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.0.50" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

    const fixturePath = path.join(TEST_DIR, "mcp-nmap-fixture.xml");
    await fs.writeFile(fixturePath, nmapXml, "utf-8");

    const data = await call("ingest_tool_output", {
      tool: "nmap",
      file: fixturePath,
    });
    assert.equal(data.hosts_discovered, 1);
    assert.equal(data.services_added, 1);
    assert.equal(data.evidence_saved, true);
  });

  it("returns isError for unsupported tool via MCP", async () => {
    const result = await client.callTool({
      name: "ingest_tool_output",
      arguments: { tool: "burpsuite", file: "/tmp/fake.xml" },
    });
    assert.equal(result.isError, true);
  });

  // ── Close + resume via MCP ──

  it("closes engagement via MCP", async () => {
    const data = await call("engagement_close", {
      status: "completed",
      executive_summary: "MCP test complete.",
    });
    assert.equal(data.status, "completed");
  });

  it("returns isError for status without active engagement", async () => {
    const result = await client.callTool({
      name: "engagement_status",
      arguments: {},
    });
    assert.equal(result.isError, true);
  });

  it("resumes engagement via MCP", async () => {
    // Get the engagement ID from the list
    const listResult = await client.callTool({
      name: "engagement_list",
      arguments: {},
    });
    const entries = JSON.parse(
      (listResult.content as Array<{ text: string }>)[0].text
    ) as Array<{ id: string; target: string }>;
    const mcpEng = entries.find((e) => e.target === "MCP Test Corp");
    assert.ok(mcpEng);

    const data = await call("engagement_resume", { id: mcpEng!.id });
    assert.ok((data as { metadata: { target: string } }).metadata.target === "MCP Test Corp");
  });
});
