# nyx-memory

Structured pentest engagement memory for AI agents. nyx-memory is an [MCP](https://modelcontextprotocol.io/) server that gives your AI coding assistant persistent, structured storage for penetration testing engagements — hosts, services, findings, credentials, evidence, attack narratives, and command logs.

## Quick start

```bash
npx nyx-memory serve
```

## MCP configuration

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "nyx-memory": {
      "command": "npx",
      "args": ["nyx-memory", "serve"]
    }
  }
}
```

### opencode

```json
{
  "mcpServers": {
    "nyx-memory": {
      "type": "stdio",
      "command": "npx",
      "args": ["nyx-memory", "serve"]
    }
  }
}
```

## Tools (19)

### Engagement lifecycle

| Tool | Description |
|------|-------------|
| `engagement_create` | Create a new pentest engagement with target, scope, and rules of engagement |
| `engagement_list` | List all engagements |
| `engagement_resume` | Resume a previous engagement |
| `engagement_status` | Get status summary of the active engagement |
| `engagement_close` | Close the active engagement |

### Host & service tracking

| Tool | Description |
|------|-------------|
| `host_discover` | Add or merge a host with services (additive merge on re-discover) |
| `host_update` | Append to a host section (enumeration, vulnerabilities, exploitation, etc.) |

### Findings

| Tool | Description |
|------|-------------|
| `finding_add` | Record a vulnerability finding with severity and CVSS |
| `finding_update` | Update finding status/notes (notes are appended) |

### Credentials

| Tool | Description |
|------|-------------|
| `credential_add` | Store a discovered credential |

### Evidence

| Tool | Description |
|------|-------------|
| `evidence_save` | Save evidence file content to the engagement |

### Narrative

| Tool | Description |
|------|-------------|
| `attack_path_update` | Append a step to the attack path narrative |
| `executive_summary_update` | Update the executive summary |

### Tracking

| Tool | Description |
|------|-------------|
| `dead_end_log` | Record a technique that didn't work (prevents re-trying) |
| `todo_add` | Add a TODO item with priority |
| `todo_complete` | Mark a TODO as completed |

### Reading

| Tool | Description |
|------|-------------|
| `notes_read` | Read findings, hosts, TODOs, credentials, attack path, command log, or search |

### Ingestion

| Tool | Description |
|------|-------------|
| `command_log` | Log a command execution |
| `ingest_tool_output` | Parse and ingest structured output from nmap, masscan, gobuster, nikto |

## CLI

```bash
# Create an engagement
nyx-memory create --target "Acme Corp" --scope 10.0.0.0/24 192.168.1.0/24

# Check status
nyx-memory status

# List engagements
nyx-memory list

# Ingest tool output
nyx-memory ingest --tool nmap --file scan.xml

# Pipe output and log it
nmap -sV 10.0.0.1 | nyx-memory log --tool nmap --target 10.0.0.1
```

## nyx-log

`nyx-log` is a transparent command wrapper that runs any command normally while capturing its output and logging it to the active engagement.

```bash
# Wrap any command — same stdout/stderr/exit code, but output is logged
nyx-log nmap -sV -p- 10.0.0.1
nyx-log gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/common.txt

# Auto-detects tool name, target IP, and structured output files
# If nmap -oX is used, the XML file is automatically ingested
nyx-log nmap -sV -oX scan.xml 10.0.0.1
```

## Data storage

Engagement data is stored as JSON files under `~/.nyx-memory/` (override with `NYX_DATA_DIR`). Each engagement gets its own directory with rendered Markdown files for easy browsing.

## License

MIT
