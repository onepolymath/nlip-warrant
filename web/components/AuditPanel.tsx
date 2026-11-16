"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { type ChainReport, verifyAudit } from "@/lib/crypto";
import { clockTime, humanReason, short } from "@/lib/format";
import type { AuditEntry, AuditView, JsonValue } from "@/lib/types";

import { Check, Cross, Shield } from "./icons";
import { Badge } from "./ui";

type Tamper = "none" | "edit" | "delete" | "truncate";

const text = (v: JsonValue | undefined): string =>
  typeof v === "string" ? v : typeof v === "number" ? String(v) : "";

function tampered(entries: AuditEntry[], mode: Tamper, target: number): AuditEntry[] {
  if (mode === "none") return entries;
  if (mode === "truncate") return entries.slice(0, -1);
  if (mode === "delete") return entries.filter((e) => e.seq !== target);
  return entries.map((e) =>
    e.seq === target
      ? { ...e, body: { ...e.body, decision: e.body.decision === "deny" ? "allow" : "deny" } }
      : e,
  );
}

export function AuditPanel({ logs }: { logs: Record<string, AuditView> }) {
  const agents = Object.keys(logs);
  const [agent, setAgent] = useState(agents.includes("payments") ? "payments" : (agents[0] ?? ""));
  const [mode, setMode] = useState<Tamper>("none");
  const [highlight, setHighlight] = useState<number | null>(null);
  const [report, setReport] = useState<ChainReport | null>(null);
  const view = logs[agent];

  const target = useMemo(() => {
    const entries = view?.entries ?? [];
    return entries.find((e) => e.body.decision === "deny")?.seq ?? 0;
  }, [view]);
  const entries = useMemo(() => tampered(view?.entries ?? [], mode, target), [view, mode, target]);

  const run = useCallback(() => {
    setReport(verifyAudit(entries, view?.checkpoint ?? null));
  }, [entries, view]);

  useEffect(() => {
    run();
  }, [run]);

  useEffect(() => {
    const onHash = () => {
      const m = /^#audit-(\w+)-(\d+)$/.exec(window.location.hash);
      if (m?.[1] && m[2] && m[1] in logs) {
        setAgent(m[1]);
        setMode("none");
        setHighlight(Number(m[2]));
        window.setTimeout(() => {
          document
            .getElementById(`row-${m[1] ?? ""}-${m[2] ?? ""}`)
            ?.scrollIntoView({ block: "center", behavior: "smooth" });
        }, 50);
      }
    };
    onHash();
    window.addEventListener("hashchange", onHash);
    return () => {
      window.removeEventListener("hashchange", onHash);
    };
  }, [logs]);

  if (!view) return null;
  const allows = view.entries.filter((e) => e.body.decision === "allow").length;

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-white/5 px-5 py-4">
        <div className="flex rounded-full bg-black/30 p-1 ring-1 ring-white/10" role="tablist">
          {agents.map((a) => (
            <button
              key={a}
              role="tab"
              aria-selected={a === agent}
              type="button"
              onClick={() => {
                setAgent(a);
                setMode("none");
                setHighlight(null);
              }}
              className={`rounded-full px-3 py-1 text-[12px] capitalize transition ${a === agent ? "bg-white/10 text-white" : "text-slate-400 hover:text-white"}`}
            >
              {a}
            </button>
          ))}
        </div>
        <span className="text-[12px] text-slate-500">
          {view.entries.length} entries · {allows} allow · {view.entries.length - allows} deny
        </span>
        <div className="ml-auto flex items-center gap-2">
          <label htmlFor="tamper" className="text-[12px] text-slate-500">
            Simulate tampering
          </label>
          <select
            id="tamper"
            value={mode}
            onChange={(e) => {
              setMode(e.target.value as Tamper);
            }}
            className="rounded-lg bg-black/40 px-2 py-1 text-[12px] text-slate-200 ring-1 ring-white/10 outline-none"
          >
            <option value="none">none</option>
            <option value="edit">flip a decision (#{target})</option>
            <option value="delete">delete entry #{target}</option>
            <option value="truncate">drop the last entry</option>
          </select>
        </div>
      </div>

      <div
        className={`flex flex-wrap items-center gap-3 px-5 py-3 text-[13px] ${report?.ok ? "bg-emerald-500/[0.06] text-emerald-200" : "bg-rose-500/[0.07] text-rose-200"}`}
        aria-live="polite"
      >
        <Shield className="size-4" />
        {report === null ? (
          "Verifying…"
        ) : report.ok ? (
          <span>
            Hash chain intact and matches the Ed25519-signed checkpoint at #{view.checkpoint?.seq}.
            Recomputed in your browser.
          </span>
        ) : (
          <span>
            Tampering detected
            {report.firstBad !== null ? ` at entry #${String(report.firstBad)}` : ""}:{" "}
            {report.problem}.
          </span>
        )}
        {view.checkpoint ? (
          <span className="ml-auto font-mono text-[11px] opacity-70">
            head {short(view.checkpoint.head, 12)}
          </span>
        ) : null}
      </div>

      <div className="max-h-[460px] overflow-auto">
        <table className="w-full text-left text-[12.5px]">
          <thead className="sticky top-0 bg-[#0b0e17]/95 text-[11px] tracking-wide text-slate-500 uppercase backdrop-blur">
            <tr>
              <th className="px-5 py-2 font-medium">#</th>
              <th className="px-2 py-2 font-medium">Time</th>
              <th className="px-2 py-2 font-medium">Boundary</th>
              <th className="px-2 py-2 font-medium">Decision</th>
              <th className="px-2 py-2 font-medium">Detail</th>
              <th className="px-2 py-2 font-medium">ECMA-434</th>
              <th className="px-5 py-2 text-right font-medium">Hash</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => {
              const bad = report?.firstBad === e.seq;
              const deny = e.body.decision === "deny";
              const sco = Array.isArray(e.body.sco) ? (e.body.sco as string[]).join(" ") : "";
              return (
                <tr
                  key={`${agent}-${String(e.seq)}`}
                  id={`row-${agent}-${String(e.seq)}`}
                  className={`border-t border-white/5 ${bad ? "bg-rose-500/10" : highlight === e.seq ? "bg-indigo-500/10" : ""}`}
                >
                  <td className="px-5 py-2 font-mono text-slate-500">{e.seq}</td>
                  <td className="px-2 py-2 font-mono text-slate-500">
                    {clockTime(Number(e.body.ts))}
                  </td>
                  <td className="px-2 py-2">
                    <Badge
                      tone={
                        e.body.boundary === "tool"
                          ? "violet"
                          : e.body.boundary === "egress"
                            ? "info"
                            : "neutral"
                      }
                    >
                      {text(e.body.boundary)}
                    </Badge>
                  </td>
                  <td className="px-2 py-2">
                    <span
                      className={`inline-flex items-center gap-1 ${deny ? "text-rose-300" : "text-emerald-300"}`}
                    >
                      {deny ? <Cross className="size-3" /> : <Check className="size-3" />}
                      {text(e.body.decision)}
                    </span>
                  </td>
                  <td
                    className="max-w-[280px] truncate px-2 py-2 text-slate-400"
                    title={text(e.body.detail)}
                  >
                    {deny
                      ? humanReason(text(e.body.reason))
                      : typeof e.body.action === "string"
                        ? e.body.action
                        : typeof e.body.mode === "string"
                          ? `${e.body.mode} · depth ${text(e.body.depth)}`
                          : `delegated → ${text(e.body.to).replace("nlip://", "")}`}
                  </td>
                  <td className="px-2 py-2 font-mono text-[11px] text-slate-500">{sco}</td>
                  <td className="px-5 py-2 text-right font-mono text-[11px] text-slate-600">
                    {short(e.hash, 10)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
