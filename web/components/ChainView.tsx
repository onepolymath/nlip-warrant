"use client";

import { useEffect, useMemo, useState } from "react";

import { type BlockCheck, checkChain } from "@/lib/crypto";
import { money, short } from "@/lib/format";
import type { Agent, Caveats, WarrantView } from "@/lib/types";

import { Check, Cross } from "./icons";
import { Badge } from "./ui";

interface Row {
  label: string;
  render: (c: Caveats) => string;
}

const ROWS: Row[] = [
  { label: "Actions", render: (c) => c.actions?.join(", ") ?? "inherit" },
  { label: "Per-call cap", render: (c) => (c.max_amount ? money(c.max_amount) : "inherit") },
  { label: "Total budget", render: (c) => (c.budget ? money(c.budget) : "inherit") },
  { label: "Payees", render: (c) => c.counterparties?.join(", ") ?? "inherit" },
  { label: "Purpose", render: (c) => c.purpose ?? "inherit" },
  {
    label: "Audiences",
    render: (c) =>
      c.audiences?.map((a) => a.replace("nlip://", "").replace(".agents.example", "")).join(", ") ??
      "inherit",
  },
  {
    label: "Further hops",
    render: (c) => (c.max_depth === undefined ? "inherit" : String(c.max_depth)),
  },
];

function nameOf(agents: Agent[], key: string): string {
  return agents.find((a) => a.key === key)?.name ?? "?";
}

export function ChainView({ warrant, agents }: { warrant: WarrantView; agents: Agent[] }) {
  const [selected, setSelected] = useState(warrant.blocks.length - 1);
  const [checks, setChecks] = useState<BlockCheck[] | null>(null);
  useEffect(() => {
    setChecks(checkChain(warrant.blocks));
  }, [warrant]);

  const people = useMemo(
    () => [warrant.blocks[0]?.payload.iss ?? "", ...warrant.blocks.map((b) => b.payload.sub)],
    [warrant],
  );

  const block = warrant.blocks[selected];
  if (!block) return null;

  return (
    <div className="grid gap-6">
      <div className="panel overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-white/5 px-5 py-4">
          {people.map((key, i) => (
            <div key={key} className="flex items-center gap-2">
              {i > 0 ? (
                <button
                  type="button"
                  onClick={() => {
                    setSelected(i - 1);
                  }}
                  className={`group flex items-center gap-1 rounded-full px-2 py-1 text-[11px] transition ${selected === i - 1 ? "bg-indigo-500/20 text-indigo-200" : "text-slate-500 hover:text-slate-300"}`}
                  aria-label={`Inspect block ${i - 1}`}
                >
                  <span className="font-mono">block {i - 1}</span>
                  <span aria-hidden>→</span>
                </button>
              ) : null}
              <span className="rounded-lg bg-white/5 px-2.5 py-1 text-sm font-medium text-white ring-1 ring-white/10">
                {nameOf(agents, key)}
              </span>
            </div>
          ))}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="text-[11px] tracking-wide text-slate-500 uppercase">
                <th className="px-5 py-3 font-medium">Caveat</th>
                {warrant.blocks.map((b, i) => (
                  <th
                    key={b.id}
                    className={`px-3 py-3 font-medium ${i === selected ? "text-indigo-300" : ""}`}
                  >
                    {b.payload.label ?? `block ${i}`}
                  </th>
                ))}
                <th className="px-3 py-3 font-medium text-emerald-300/90">Effective</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map((row) => (
                <tr key={row.label} className="border-t border-white/5 align-top">
                  <td className="px-5 py-2.5 text-slate-400">{row.label}</td>
                  {warrant.blocks.map((b, i) => {
                    const value = row.render(b.payload.caveats);
                    const inherit = value === "inherit";
                    return (
                      <td
                        key={b.id}
                        className={`px-3 py-2.5 ${inherit ? "text-slate-600 italic" : "text-slate-200"} ${i === selected ? "bg-indigo-500/[0.06]" : ""}`}
                      >
                        {value}
                      </td>
                    );
                  })}
                  <td className="px-3 py-2.5 font-medium text-emerald-200">
                    {row.render(warrant.effective)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel grid gap-6 p-5 lg:grid-cols-[1fr_1.2fr]">
        <div>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">
              Block {selected} · {block.payload.label}
            </h3>
            <Badge tone="violet">Ed25519</Badge>
          </div>
          <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-[12px]">
            <dt className="text-slate-500">issuer</dt>
            <dd className="truncate font-mono text-slate-300">
              {nameOf(agents, block.payload.iss)} · {short(block.payload.iss, 14)}
            </dd>
            <dt className="text-slate-500">holder</dt>
            <dd className="truncate font-mono text-slate-300">
              {nameOf(agents, block.payload.sub)} · {short(block.payload.sub, 14)}
            </dd>
            <dt className="text-slate-500">block id</dt>
            <dd className="truncate font-mono text-slate-300">{short(block.id, 24)}</dd>
            <dt className="text-slate-500">parent</dt>
            <dd className="truncate font-mono text-slate-300">
              {block.payload.parent ? short(block.payload.parent, 24) : "— (root)"}
            </dd>
            <dt className="text-slate-500">valid for</dt>
            <dd className="font-mono text-slate-300">
              {Math.round((block.payload.exp - block.payload.nbf) / 60)} min
            </dd>
          </dl>
          <div className="mt-4 grid grid-cols-3 gap-2 text-[12px]">
            {(["signature", "id", "linked"] as const).map((k) => {
              const ok = checks?.[selected]?.[k];
              const label = { signature: "Signature", id: "Content hash", linked: "Chain link" }[k];
              return (
                <div
                  key={k}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-2 ring-1 ring-inset ${ok === undefined ? "text-slate-500 ring-white/10" : ok ? "bg-emerald-500/5 text-emerald-300 ring-emerald-400/20" : "bg-rose-500/5 text-rose-300 ring-rose-400/20"}`}
                >
                  {ok === undefined ? "…" : ok ? <Check /> : <Cross />}
                  {label}
                </div>
              );
            })}
          </div>
          <p className="mt-2 text-[11px] text-slate-500">
            Re-verified in your browser with @noble/curves.
          </p>
        </div>
        <pre className="max-h-64 overflow-auto rounded-lg bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-slate-400 ring-1 ring-white/5">
          {JSON.stringify(block.payload, null, 2)}
        </pre>
      </div>
    </div>
  );
}
