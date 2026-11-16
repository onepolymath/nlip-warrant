import data from "@/public/data/demo.json";

import type { Snapshot } from "./types";

export const snapshot = data as unknown as Snapshot;

export function agentByKey(key: string): string {
  return snapshot.agents.find((a) => a.key === key)?.name ?? "unknown";
}
