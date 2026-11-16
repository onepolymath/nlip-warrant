import { pct } from "@/lib/format";
import type { Results } from "@/lib/types";

import { Badge } from "./ui";

function cellTone(rate: number, residual: boolean): string {
  if (residual) return "bg-slate-500/10 text-slate-400";
  if (rate === 0) return "bg-emerald-500/15 text-emerald-200";
  if (rate < 0.5) return "bg-amber-500/15 text-amber-200";
  return "bg-rose-500/15 text-rose-200";
}

export function Evaluation({ results }: { results: Results }) {
  const names = Object.keys(results.defenses);
  const depth = results.latency.by_depth;
  const maxUs = Math.max(...depth.map((d) => d.ingress_us));
  const http = results.latency.http.depth3;
  const ours = results.defenses["NLIP-Warrant"];

  return (
    <div className="space-y-6">
      <div className="panel overflow-x-auto">
        <table className="w-full min-w-[760px] text-[12.5px]">
          <thead>
            <tr className="text-[11px] tracking-wide text-slate-500 uppercase">
              <th className="px-5 py-3 text-left font-medium">
                Attack (success rate, {results.meta.trials} trials each)
              </th>
              {names.map((n) => (
                <th
                  key={n}
                  className={`px-2 py-3 text-center font-medium ${n === "NLIP-Warrant" ? "text-indigo-300" : ""}`}
                >
                  <span title={n}>{results.defenses[n]?.short}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.attacks.map((a) => (
              <tr key={a.key} className="border-t border-white/5">
                <td className="px-5 py-2 text-slate-300">
                  <span className="mr-2 font-mono text-[11px] text-slate-600">{a.key}</span>
                  {a.title}
                </td>
                {names.map((n) => {
                  const rate = a.success[n] ?? 0;
                  return (
                    <td key={n} className="px-1.5 py-1.5 text-center">
                      <span
                        className={`inline-block w-full rounded-md py-1 font-mono text-[11.5px] ${cellTone(rate, a.residual)} ${n === "NLIP-Warrant" ? "ring-1 ring-indigo-400/30" : ""}`}
                      >
                        {pct(rate)}
                      </span>
                    </td>
                  );
                })}
              </tr>
            ))}
            <tr className="border-t border-white/10 text-slate-200">
              <td className="px-5 py-3 font-medium">Attack classes fully blocked</td>
              {names.map((n) => (
                <td key={n} className="px-2 py-3 text-center font-mono text-[12px]">
                  {results.defenses[n]?.classes_fully_blocked}/{results.defenses[n]?.classes}
                </td>
              ))}
            </tr>
            <tr className="border-t border-white/5 text-slate-400">
              <td className="px-5 py-3">False refusals of legitimate requests</td>
              {names.map((n) => (
                <td key={n} className="px-2 py-3 text-center font-mono text-[12px]">
                  {results.defenses[n]?.false_refusals}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
        <p className="border-t border-white/5 px-5 py-3 text-[12px] text-slate-500">
          Baselines: no authorization, per-service static API keys, an OAuth 2.0 bearer token
          forwarded down the chain, and OAuth with RFC 8693 token exchange at every hop. Ablations
          remove proof-of-possession (W/o PoP) or the Type-3 tool-boundary check (W/o T3). R1 is the
          residual risk no delegation scheme can remove: a hijacked agent misusing authority it
          legitimately holds.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <div className="panel p-5 md:col-span-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">
              Ingress latency by delegation depth
            </h3>
            <Badge>
              median, {results.latency.platform.cores} vCPU · Python{" "}
              {results.latency.platform.python}
            </Badge>
          </div>
          <div className="mt-5 flex h-44 items-end gap-3">
            {depth.map((d) => (
              <div key={d.depth} className="flex flex-1 flex-col items-center gap-1.5">
                <span className="font-mono text-[10.5px] text-slate-400">
                  {Math.round(d.ingress_us)}
                </span>
                <div
                  className="flex w-full flex-col justify-end overflow-hidden rounded-md"
                  style={{ height: `${String((d.ingress_us / maxUs) * 140)}px` }}
                >
                  <div className="flex-1 bg-indigo-400/25" />
                  <div
                    className="bg-indigo-400/80"
                    style={{ height: `${String((d.verify_us / d.ingress_us) * 100)}%` }}
                  />
                </div>
                <span className="font-mono text-[11px] text-slate-500">{d.depth}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[12px] text-slate-500">
            µs per inbound message (solid: chain verification, ~1 Ed25519 check per block; faint:
            proof, replay cache, audit). Type-3 tool check: {Math.round(depth[2]?.tool_us ?? 0)} µs.
            Warrant grows {String((depth[1]?.warrant_bytes ?? 0) - (depth[0]?.warrant_bytes ?? 0))}{" "}
            B per hop.
          </p>
        </div>
        <div className="panel flex flex-col justify-between p-5">
          <div>
            <h3 className="text-sm font-semibold text-white">End to end over nlip_server</h3>
            <p className="mt-1 text-[12px] text-slate-500">
              HTTP POST /nlip, 3-block chain, in-process ASGI
            </p>
          </div>
          <div className="mt-4 space-y-3 font-mono text-[13px]">
            <div className="flex justify-between">
              <span className="text-slate-500">unguarded</span>
              <span className="text-slate-200">
                {(http ? http.plain.median_us / 1000 : 0).toFixed(2)} ms
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">NLIP-Warrant</span>
              <span className="text-slate-200">
                {(http ? http.guarded.median_us / 1000 : 0).toFixed(2)} ms
              </span>
            </div>
            <div className="flex justify-between border-t border-white/10 pt-3">
              <span className="text-slate-400">overhead</span>
              <span className="text-indigo-300">
                +{(http ? http.overhead_median_us / 1000 : 0).toFixed(2)} ms
              </span>
            </div>
          </div>
          <p className="mt-4 text-[12px] text-slate-500">
            {ours?.false_refusals ?? 0} false refusals across {ours?.legit_requests ?? 0} legitimate
            requests.
          </p>
        </div>
      </div>
    </div>
  );
}
