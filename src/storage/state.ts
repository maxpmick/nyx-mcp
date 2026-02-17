import * as path from "node:path";
import { readJSON, writeJSON, withLock } from "./engine.js";
import type { AppState, IndexEntry } from "../types.js";

export function resolveDataDir(): string {
  return process.env.NYX_DATA_DIR || path.resolve("engagements");
}

function statePath(): string {
  return path.join(resolveDataDir(), "state.json");
}

function indexPath(): string {
  return path.join(resolveDataDir(), "index.json");
}

function lockPath(): string {
  return path.join(resolveDataDir(), ".nyx.lock");
}

export function getEngagementDir(id: string): string {
  return path.join(resolveDataDir(), id);
}

export function getMetadataPath(id: string): string {
  return path.join(getEngagementDir(id), "metadata.json");
}

// ── State management ──

export async function getState(): Promise<AppState> {
  return readJSON<AppState>(statePath(), { current_engagement_id: null });
}

export async function setState(state: AppState): Promise<void> {
  await writeJSON(statePath(), state);
}

export async function getActiveEngagementId(): Promise<string | null> {
  const state = await getState();
  return state.current_engagement_id;
}

export async function setActiveEngagement(id: string): Promise<void> {
  await setState({ current_engagement_id: id });
}

export async function clearActiveEngagement(): Promise<void> {
  await setState({ current_engagement_id: null });
}

export async function requireActiveEngagement(): Promise<string> {
  const id = await getActiveEngagementId();
  if (!id) {
    throw Object.assign(new Error("No active engagement. Create or resume one first."), {
      code: "no_active_engagement",
    });
  }
  return id;
}

// ── Index management ──

export async function getIndex(): Promise<IndexEntry[]> {
  return readJSON<IndexEntry[]>(indexPath(), []);
}

export async function updateIndexEntry(entry: IndexEntry): Promise<void> {
  await withLock(lockPath(), async () => {
    const index = await getIndex();
    const existing = index.findIndex((e) => e.id === entry.id);
    if (existing >= 0) {
      index[existing] = entry;
    } else {
      index.push(entry);
    }
    await writeJSON(indexPath(), index);
  });
}

export async function removeIndexEntry(id: string): Promise<void> {
  await withLock(lockPath(), async () => {
    const index = await getIndex();
    const filtered = index.filter((e) => e.id !== id);
    await writeJSON(indexPath(), filtered);
  });
}
