import { clockTime, humanReason, money, short } from "@/lib/format";
import type { Agent, RevocationView, WarrantView } from "@/lib/types";

import { Badge } from "./ui";

function holder(agents: Agent[], w: WarrantView): string {
  const key = w.blocks.at(-1)?.payload.sub ?? "";
  return agents.find((a) => a.key === key)?.name ?? "?";
}

const tone = (status: string) =>
  status === "active"
    ? "allow"
    : status === "revoked"
      ? "warn"
      : status === "expired"
        ? "neutral"
        : "block";

export function Warrants({
  warrants,
  revocations,
  agents,
}: {
  warrants: WarrantView[];
  revocations: RevocationView[];
  agents: Agent[];
}) {
  const roots = new Map<string, number>();
  for (const w of warrants) if (!roots.has(w.root)) roots.set(w.root, roots.size + 1);
  return (
    <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
      <div className="panel overflow-hidden">
        <div className="max-h-[420px] overflow-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead className="sticky top-0 bg-[#0b0e17]/95 text-[11px] tracking-wide text-slate-500 uppercase backdrop-blur">
              <tr>
                <th className="px-5 py-2.5 font-medium">Leaf</th>
                <th className="px-2 py-2.5 font-medium">Root</th>
                <th className="px-2 py-2.5 font-medium">Depth</th>
                <th className="px-2 py-2.5 font-medium">Holder</th>
                <th className="px-2 py-2.5 font-medium">Cap</th>
                <th className="px-2 py-2.5 font-medium">Size</th>
                <th className="px-5 py-2.5 font-medium">Status now</th>
              </tr>
            </thead>
            <tbody>
              {warrants.map((w) => (
                <tr key={w.leaf} className="border-t border-white/5">
                  <td className="px-5 py-2 font-mono text-slate-400">{short(w.leaf, 10)}</td>
                  <td className="px-2 py-2 font-mono text-slate-500">R{roots.get(w.root)}</td>
                  <td className="px-2 py-2 text-slate-300">{w.blocks.length}</td>
                  <td className="px-2 py-2 text-slate-200">{holder(agents, w)}</td>
                  <td className="px-2 py-2 text-slate-300">{money(w.effective.max_amount)}</td>
                  <td className="px-2 py-2 font-mono text-slate-500">
                    {(w.token_bytes / 1024).toFixed(1)} KB
                  </td>
                  <td className="px-5 py-2">
                    <Badge tone={tone(w.status)}>{humanReason(w.status)}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="space-y-3">
        {revocations.map((r) => (
          <div key={r.sig} className="panel p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-white">Revocation by {r.by_name}</span>
              <Badge tone={r.honoured ? "allow" : "block"}>
                {r.honoured ? "honoured" : "ignored"}
              </Badge>
            </div>
            <p className="mt-1.5 text-[12.5px] text-slate-400">“{r.reason}”</p>
            <p className="mt-2 font-mono text-[11px] text-slate-500">
              block {short(r.block_id, 12)} · {clockTime(r.at)}
            </p>
            <p className="mt-2 text-[12px] text-slate-500">
              {r.honoured
                ? "Signed by the root issuer, so every warrant derived from that block stops working."
                : "Validly signed, but not by an issuer on the chain, so verifiers disregard it."}
            </p>
          </div>
        ))}
        <p className="px-1 text-[12px] text-slate-500">
          Each request mints a fresh, short-lived child warrant; R1 is Alice’s main grant and R2 the
          five-minute grant used in the expiry step.
        </p>
      </div>
    </div>
  );
}
