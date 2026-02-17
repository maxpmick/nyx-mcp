import * as fs from "node:fs/promises";
import * as path from "node:path";
import lockfile from "proper-lockfile";

export async function ensureDir(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

export async function readJSON<T>(filePath: string, defaultValue: T): Promise<T> {
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    return JSON.parse(raw) as T;
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return defaultValue;
    }
    throw err;
  }
}

export async function writeJSON<T>(filePath: string, data: T): Promise<void> {
  await ensureDir(path.dirname(filePath));
  const tmpPath = `${filePath}.tmp.${process.pid}`;
  const content = JSON.stringify(data, null, 2) + "\n";
  await fs.writeFile(tmpPath, content, "utf-8");
  await fs.rename(tmpPath, filePath);
}

export async function writeFileAtomic(filePath: string, content: string): Promise<void> {
  await ensureDir(path.dirname(filePath));
  const tmpPath = `${filePath}.tmp.${process.pid}`;
  await fs.writeFile(tmpPath, content, "utf-8");
  await fs.rename(tmpPath, filePath);
}

export async function withLock<T>(lockPath: string, fn: () => Promise<T>): Promise<T> {
  await ensureDir(path.dirname(lockPath));

  // Ensure the lock target file exists
  try {
    await fs.access(lockPath);
  } catch {
    await fs.writeFile(lockPath, "", "utf-8");
  }

  const release = await lockfile.lock(lockPath, {
    stale: 10000,
    retries: {
      retries: 5,
      minTimeout: 200,
      maxTimeout: 5000,
    },
  });

  try {
    return await fn();
  } finally {
    await release();
  }
}
