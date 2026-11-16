/**
 * Browser-side re-verification of NLIP-Warrant artefacts.
 *
 * Mirrors the Python reference exactly: canonical JSON (sorted keys, no whitespace, no floats),
 * domain-separated Ed25519 signatures over blocks and checkpoints, and the SHA-256 audit chain.
 * Nothing here trusts the `verified` flags in the snapshot; it recomputes everything.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

import type { AuditEntry, Block, Checkpoint, JsonValue } from "./types";

const BLOCK_DOMAIN = "nlip-warrant/v1/block\u0000";
const AUDIT_DOMAIN = "nlip-warrant/v1/audit\u0000";
const CHECKPOINT_DOMAIN = "nlip-warrant/v1/checkpoint\u0000";
export const GENESIS = "0".repeat(64);

export function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("non-integer number in canonical JSON");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  throw new Error(`unsupported type ${typeof value}`);
}

export function b64urlToBytes(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const raw = atob(b64);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

export function sha256Hex(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text)));
}

function ed25519Valid(keyId: string, message: string, signature: string): boolean {
  try {
    return ed25519.verify(b64urlToBytes(signature), utf8ToBytes(message), b64urlToBytes(keyId));
  } catch {
    return false;
  }
}

export function blockId(block: Pick<Block, "payload" | "sig">): string {
  return sha256Hex(canonical({ p: block.payload, s: block.sig }));
}

export interface BlockCheck {
  signature: boolean;
  id: boolean;
  linked: boolean;
}

/** Signature, content address and parent linkage for every block of a chain. */
export function checkChain(blocks: Block[]): BlockCheck[] {
  return blocks.map((block, i) => {
    const prev = blocks[i - 1];
    return {
      signature: ed25519Valid(
        block.payload.iss,
        BLOCK_DOMAIN + canonical(block.payload),
        block.sig,
      ),
      id: blockId(block) === block.id,
      linked:
        i === 0
          ? block.payload.parent === undefined
          : prev !== undefined &&
            block.payload.parent === prev.id &&
            block.payload.iss === prev.payload.sub,
    };
  });
}

export function entryHash(prev: string, body: Record<string, JsonValue>): string {
  return sha256Hex(AUDIT_DOMAIN + prev + canonical(body));
}

export interface ChainReport {
  ok: boolean;
  firstBad: number | null;
  problem: string | null;
  checkpoint: "valid" | "invalid" | "mismatch" | "none";
}

export function verifyAudit(entries: AuditEntry[], checkpoint: Checkpoint | null): ChainReport {
  let prev = GENESIS;
  for (const [i, e] of entries.entries()) {
    if (e.seq !== i) return { ok: false, firstBad: i, problem: "sequence gap", checkpoint: "none" };
    if (e.prev !== prev)
      return { ok: false, firstBad: i, problem: "broken link", checkpoint: "none" };
    if (entryHash(prev, e.body) !== e.hash) {
      return {
        ok: false,
        firstBad: i,
        problem: "content does not match its hash",
        checkpoint: "none",
      };
    }
    prev = e.hash;
  }
  if (!checkpoint) return { ok: true, firstBad: null, problem: null, checkpoint: "none" };
  const signed = canonical({
    seq: checkpoint.seq,
    head: checkpoint.head,
    ts: checkpoint.ts,
    by: checkpoint.by,
  });
  if (!ed25519Valid(checkpoint.by, CHECKPOINT_DOMAIN + signed, checkpoint.sig)) {
    return {
      ok: false,
      firstBad: null,
      problem: "checkpoint signature invalid",
      checkpoint: "invalid",
    };
  }
  const at = entries[checkpoint.seq];
  if (at?.hash !== checkpoint.head) {
    return {
      ok: false,
      firstBad: checkpoint.seq,
      problem: "differs from signed checkpoint",
      checkpoint: "mismatch",
    };
  }
  return { ok: true, firstBad: null, problem: null, checkpoint: "valid" };
}
