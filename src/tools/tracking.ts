import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { DeadEnd, Todo } from "../types.js";
import { loadActiveMetadata, saveMetadataAndRender } from "./engagement.js";

function now(): string {
  return new Date().toISOString();
}

function nextTodoId(existing: Todo[]): string {
  let max = 0;
  for (const t of existing) {
    const n = parseInt(t.id.replace("T-", ""), 10);
    if (n > max) max = n;
  }
  return `T-${String(max + 1).padStart(3, "0")}`;
}

export async function logDeadEnd(params: {
  technique: string;
  target: string;
  reason: string;
}): Promise<DeadEnd> {
  const meta = await loadActiveMetadata();

  const entry: DeadEnd = {
    timestamp: now(),
    technique: params.technique,
    target: params.target,
    reason: params.reason,
  };

  meta.dead_ends.push(entry);
  await saveMetadataAndRender(meta);
  return entry;
}

export async function addTodo(params: {
  description: string;
  priority?: "high" | "medium" | "low";
}): Promise<Todo> {
  const meta = await loadActiveMetadata();
  const id = nextTodoId(meta.todos);

  const todo: Todo = {
    id,
    description: params.description,
    priority: params.priority || "medium",
    status: "pending",
    created_at: now(),
    completed_at: null,
  };

  meta.todos.push(todo);
  await saveMetadataAndRender(meta);
  return todo;
}

export async function completeTodo(params: { id: string }): Promise<Todo> {
  const meta = await loadActiveMetadata();
  const todo = meta.todos.find((t) => t.id === params.id);
  if (!todo) {
    throw Object.assign(new Error(`TODO '${params.id}' not found.`), { code: "todo_not_found" });
  }

  todo.status = "completed";
  todo.completed_at = now();
  await saveMetadataAndRender(meta);
  return todo;
}

export function registerTrackingTools(server: McpServer): void {
  server.tool(
    "dead_end_log",
    "Log a technique that didn't work (dead end)",
    {
      technique: z.string().describe("Technique or attack that was attempted"),
      target: z.string().describe("Target of the attempt"),
      reason: z.string().describe("Why it failed or was a dead end"),
    },
    async (args) => {
      const result = await logDeadEnd(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "todo_add",
    "Add a TODO item to the engagement",
    {
      description: z.string().describe("TODO description"),
      priority: z.enum(["high", "medium", "low"]).optional().describe("Priority level (default: medium)"),
    },
    async (args) => {
      const result = await addTodo(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "todo_complete",
    "Mark a TODO as completed",
    {
      id: z.string().describe("TODO ID (e.g., T-001)"),
    },
    async (args) => {
      const result = await completeTodo(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
