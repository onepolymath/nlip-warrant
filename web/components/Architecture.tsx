import { Fragment } from "react";

const nodes = [
  { name: "Alice", sub: "user client · root key", chips: [["slate", "issues root warrant"]] },
  {
    name: "Concierge",
    sub: "planner agent",
    chips: [
      ["sky", "Type-1 ingress"],
      ["violet", "Type-2 egress"],
    ],
  },
  {
    name: "Procurement",
    sub: "router agent",
    chips: [
      ["sky", "Type-2 ingress"],
      ["violet", "Type-2 egress"],
    ],
  },
  {
    name: "Payments",
    sub: "tool executor",
    chips: [
      ["sky", "Type-2 ingress"],
      ["emerald", "Type-3 tool boundary"],
    ],
  },
] as const;

type Tone = (typeof nodes)[number]["chips"][number][0];

export function Architecture() {
  return (
    <div className="panel relative overflow-hidden p-6">
      <div className="grid-bg pointer-events-none absolute inset-0" aria-hidden />
      <div className="relative grid gap-3 md:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr] md:items-stretch">
        {nodes.map((n, i) => (
          <Fragment key={n.name}>
            {i > 0 ? (
              <div className="flex flex-col items-center justify-center px-1 text-[10px] text-slate-500">
                <span className="font-mono">NLIP / HTTP</span>
                <span aria-hidden className="text-lg leading-none text-indigo-300">
                  ⟶
                </span>
                <span className="font-mono text-indigo-300/80">warrant + proof</span>
              </div>
            ) : null}
            <div className="rounded-xl bg-[#0d1120] p-3.5 ring-1 ring-white/10">
              <p className="text-sm font-semibold text-white">{n.name}</p>
              <p className="text-[11px] text-slate-500">{n.sub}</p>
              <div className="mt-2.5 flex flex-wrap gap-1">
                {n.chips.map(([tone, label]) => (
                  <Chip key={label} tone={tone}>
                    {label}
                  </Chip>
                ))}
              </div>
            </div>
          </Fragment>
        ))}
      </div>
      <p className="relative mt-5 max-w-4xl text-[12.5px] leading-relaxed text-slate-400">
        Every hop is an ECMA-430 message whose{" "}
        <span className="font-mono text-slate-300">token</span> submessages carry the warrant chain
        and a proof of possession. The guard decides with boundary-visible data only: the message,
        the structured tool call, local state (replay cache, spend ledger, revocations) and policy.
        No agent internals, no hidden reasoning.
      </p>
    </div>
  );
}

function Chip({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  const t = {
    sky: "text-sky-300 ring-sky-400/25 bg-sky-500/10",
    violet: "text-indigo-300 ring-indigo-400/25 bg-indigo-500/10",
    emerald: "text-emerald-300 ring-emerald-400/25 bg-emerald-500/10",
    slate: "text-slate-300 ring-white/10 bg-white/5",
  }[tone];
  return (
    <span className={`rounded-md px-1.5 py-0.5 text-[10.5px] ring-1 ring-inset ${t}`}>
      {children}
    </span>
  );
}
