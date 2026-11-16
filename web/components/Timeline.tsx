"use client";

import { useEffect, useState } from "react";

import { humanReason } from "@/lib/format";
import type { ScenarioEvent } from "@/lib/types";

import { Check, Cross } from "./icons";
import { Badge } from "./ui";

const kindTone = { legit: "allow", attack: "block", admin: "info" } as const;

export function Timeline({ events }: { events: ScenarioEvent[] }) {
  const [active, setActive] = useState(0);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    const id = window.setInterval(() => {
      setActive((i) => {
        if (i >= events.length - 1) {
          setPlaying(false);
          return i;
        }
        return i + 1;
      });
    }, 1800);
    return () => {
      window.clearInterval(id);
    };
  }, [playing, events.length]);

  const event = events[active];
  if (!event) return null;
  const blocked = events.filter((e) => e.kind !== "legit" && e.outcome === "block").length;

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_1.15fr]">
      <div className="panel p-2">
        <div className="flex items-center justify-between px-3 py-2">
          <p className="text-[12px] text-slate-500">
            {events.length} steps · {blocked} attacks stopped · £0 lost
          </p>
          <button
            type="button"
            onClick={() => {
              if (active >= events.length - 1) setActive(0);
              setPlaying((p) => !p);
            }}
            className="rounded-full bg-indigo-500/90 px-3 py-1 text-[12px] font-medium text-white shadow-lg shadow-indigo-500/20 transition hover:bg-indigo-400"
          >
            {playing ? "Pause" : "▶ Replay scenario"}
          </button>
        </div>
        <ol className="space-y-0.5">
          {events.map((e, i) => {
            const ok = e.outcome === e.expect;
            return (
              <li key={e.step}>
                <button
                  type="button"
                  onClick={() => {
                    setPlaying(false);
                    setActive(i);
                  }}
                  className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left transition ${i === active ? "bg-white/[0.06] ring-1 ring-white/10" : "hover:bg-white/[0.03]"}`}
                >
                  <span className="w-5 text-right font-mono text-[11px] text-slate-600">
                    {e.step}
                  </span>
                  <span
                    className={`flex size-5 items-center justify-center rounded-full ${e.outcome === "allow" ? "bg-emerald-500/15 text-emerald-300" : "bg-rose-500/15 text-rose-300"}`}
                  >
                    {e.outcome === "allow" ? (
                      <Check className="size-3" />
                    ) : (
                      <Cross className="size-3" />
                    )}
                  </span>
                  <span className="flex-1 truncate text-[13px] text-slate-200">{e.title}</span>
                  <Badge tone={kindTone[e.kind]}>{e.kind}</Badge>
                  {!ok ? <Badge tone="warn">unexpected</Badge> : null}
                </button>
              </li>
            );
          })}
        </ol>
      </div>

      <div key={event.step} className="panel rise flex flex-col p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={kindTone[event.kind]}>{event.kind}</Badge>
          <Badge tone={event.outcome === "allow" ? "allow" : "block"}>
            {event.outcome === "allow" ? "Allowed" : `Blocked · ${humanReason(event.reason)}`}
          </Badge>
          {event.blocked_at ? <Badge tone="neutral">at {event.blocked_at}</Badge> : null}
          <span className="ml-auto font-mono text-[11px] text-slate-600">t+{event.t}s</span>
        </div>
        <h3 className="mt-4 text-xl font-semibold text-white">
          {event.step}. {event.title}
        </h3>
        <p className="mt-2 text-[14px] leading-relaxed text-slate-400">{event.narrative}</p>

        {event.results.length ? (
          <div className="mt-5">
            <p className="text-[11px] font-medium tracking-wide text-slate-500 uppercase">
              What the agents did
            </p>
            <ul className="mt-2 space-y-1.5">
              {event.results.map((r, i) => (
                <li
                  key={i}
                  className="flex items-center gap-2 rounded-lg bg-black/30 px-3 py-2 text-[13px] ring-1 ring-white/5"
                >
                  {r.status === "done" ? (
                    <Check className="size-3.5 text-emerald-300" />
                  ) : (
                    <Cross className="size-3.5 text-rose-300" />
                  )}
                  <span className="font-mono text-slate-300">{r.tool}</span>
                  {r.to ? <span className="text-slate-500">→ {r.to}</span> : null}
                  <span
                    className={`ml-auto text-[12px] ${r.status === "done" ? "text-emerald-300" : "text-rose-300"}`}
                  >
                    {r.status === "done" ? "executed" : humanReason(r.reason)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="mt-5">
          <p className="text-[11px] font-medium tracking-wide text-slate-500 uppercase">
            Audit entries written
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {event.audit_refs.map((r) => (
              <a
                key={`${r.agent}-${String(r.seq)}`}
                href={`#audit-${r.agent}-${String(r.seq)}`}
                className={`rounded-md px-2 py-1 font-mono text-[11px] ring-1 ring-inset transition hover:brightness-125 ${r.decision === "allow" ? "bg-emerald-500/5 text-emerald-300/90 ring-emerald-400/15" : "bg-rose-500/5 text-rose-300/90 ring-rose-400/15"}`}
              >
                {r.agent}#{r.seq} {r.boundary}
              </a>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
