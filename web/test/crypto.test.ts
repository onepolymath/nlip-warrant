import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { blockId, canonical, checkChain, verifyAudit } from "../lib/crypto";
import type { Snapshot } from "../lib/types";

const snap = JSON.parse(
  readFileSync(new URL("../public/data/demo.json", import.meta.url), "utf8"),
) as Snapshot;

describe("canonical JSON", () => {
  it("sorts keys and strips whitespace like the Python reference", () => {
    expect(canonical({ b: 1, a: [true, null, "é"] })).toBe('{"a":[true,null,"é"],"b":1}');
  });
  it("rejects floats", () => {
    expect(() => canonical({ x: 1.5 })).toThrow();
  });
});

describe("snapshot artefacts verify in JavaScript", () => {
  it("every honest warrant block has a valid signature, id and link", () => {
    for (const w of snap.warrants.filter((w) => w.status !== "attenuation_widened")) {
      for (const c of checkChain(w.blocks))
        expect(c).toEqual({ signature: true, id: true, linked: true });
    }
  });

  it("content addresses match Python's", () => {
    const w = snap.warrants[0];
    expect(w).toBeDefined();
    if (w?.blocks[0]) expect(blockId(w.blocks[0])).toBe(w.blocks[0].id);
  });

  it("every agent's audit log and checkpoint verify", () => {
    for (const view of Object.values(snap.audit)) {
      expect(verifyAudit(view.entries, view.checkpoint)).toMatchObject({
        ok: true,
        checkpoint: "valid",
      });
    }
  });

  it("detects edits, deletions and truncation", () => {
    const view = snap.audit.payments;
    expect(view).toBeDefined();
    if (!view) return;
    const edited = view.entries.map((e, i) =>
      i === 2 ? { ...e, body: { ...e.body, decision: "allow" } } : e,
    );
    expect(verifyAudit(edited, null).firstBad).toBe(2);
    expect(
      verifyAudit(
        view.entries.filter((e) => e.seq !== 1),
        null,
      ).ok,
    ).toBe(false);
    expect(verifyAudit(view.entries.slice(0, -1), view.checkpoint).ok).toBe(false);
    expect(verifyAudit(view.entries.slice(0, -1), null).ok).toBe(true);
  });

  it("rejects a tampered block signature", () => {
    const w = snap.warrants.find((x) => x.blocks.length === 3);
    expect(w).toBeDefined();
    if (!w) return;
    const forged = w.blocks.map((b, i) =>
      i === 2
        ? { ...b, payload: { ...b.payload, caveats: { ...b.payload.caveats, max_depth: 9 } } }
        : b,
    );
    expect(checkChain(forged)[2]?.signature).toBe(false);
  });
});
