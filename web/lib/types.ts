/** Shapes of the snapshot written by `nlip-warrant demo --export` (schema demo-snapshot@1). */

export interface Money {
  currency: string;
  minor: number;
}

export interface Caveats {
  actions?: string[];
  max_amount?: Money;
  budget?: Money;
  counterparties?: string[];
  purpose?: string;
  audiences?: string[];
  max_depth?: number;
}

export interface BlockPayload {
  v: number;
  jti: string;
  parent?: string;
  iss: string;
  sub: string;
  iat: number;
  nbf: number;
  exp: number;
  caveats: Caveats;
  label?: string;
}

export interface Block {
  id: string;
  payload: BlockPayload;
  sig: string;
}

export interface WarrantView {
  leaf: string;
  root: string;
  status: string;
  status_detail: string | null;
  effective: Caveats;
  token_bytes: number;
  blocks: Block[];
}

export interface Agent {
  id: string;
  name: string;
  role: string;
  key: string;
  audience: string | null;
}

export interface RevocationView {
  block_id: string;
  by: string;
  by_name: string;
  at: number;
  reason: string;
  sig: string;
  honoured: boolean;
}

export interface AuditRef {
  agent: string;
  seq: number;
  boundary?: string;
  decision?: string;
  reason?: string;
}

export interface ScenarioEvent {
  step: number;
  kind: "legit" | "attack" | "admin";
  title: string;
  narrative: string;
  expect: "allow" | "block";
  outcome: "allow" | "block";
  reason: string | null;
  blocked_at: string | null;
  results: { tool: string; status: string; reason?: string; ref?: string; to?: string }[];
  audit_refs: AuditRef[];
  t: number;
}

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

export interface AuditEntry {
  seq: number;
  prev: string;
  hash: string;
  body: Record<string, JsonValue>;
}

export interface Checkpoint {
  seq: number;
  head: string;
  ts: number;
  by: string;
  sig: string;
}

export interface AuditView {
  entries: AuditEntry[];
  checkpoint: Checkpoint | null;
  verified: boolean;
}

export interface DefenseSummary {
  short: string;
  family: "ours" | "ablation" | "baseline";
  classes_fully_blocked: number;
  classes: number;
  mean_attack_success: number;
  false_refusals: number;
  legit_requests: number;
}

export interface AttackSummary {
  key: string;
  title: string;
  group: string;
  residual: boolean;
  success: Record<string, number>;
  ci95: Record<string, [number, number]>;
}

export interface LatencyRow {
  depth: number;
  warrant_bytes: number;
  proof_bytes: number;
  verify_us: number;
  ingress_us: number;
  ingress_p95_us: number;
  tool_us: number;
}

export interface Results {
  meta: { trials: number; seed: number; elapsed_s: number };
  defenses: Record<string, DefenseSummary>;
  attacks: AttackSummary[];
  latency: {
    platform: { python: string; machine: string; cpu: string; cores: number };
    by_depth: LatencyRow[];
    bearer_hmac_us: number;
    http: Record<
      string,
      {
        plain: { median_us: number };
        guarded: { median_us: number };
        overhead_median_us: number;
      }
    >;
  };
}

export interface Snapshot {
  schema: string;
  clock: { start: number; end: number };
  agents: Agent[];
  warrants: WarrantView[];
  revocations: RevocationView[];
  events: ScenarioEvent[];
  bank: { kind: string; to: string; amount: number; currency: string; ref: string }[];
  audit: Record<string, AuditView>;
  results: Results | null;
}
