import type { ToolParser } from "../types.js";
import { nmapParser } from "./nmap.js";
import { masscanParser } from "./masscan.js";
import { gobusterParser } from "./gobuster.js";
import { niktoParser } from "./nikto.js";

const parserRegistry = new Map<string, ToolParser>();

parserRegistry.set("nmap", nmapParser);
parserRegistry.set("masscan", masscanParser);
parserRegistry.set("gobuster", gobusterParser);
parserRegistry.set("ffuf", gobusterParser);
parserRegistry.set("feroxbuster", gobusterParser);
parserRegistry.set("nikto", niktoParser);

export function getParser(tool: string): ToolParser | undefined {
  return parserRegistry.get(tool.toLowerCase());
}

export function getSupportedParsers(): string[] {
  return Array.from(new Set(Array.from(parserRegistry.values()).map((p) => p.name)));
}

export { parserRegistry };
