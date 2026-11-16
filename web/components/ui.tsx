import type { ReactNode } from "react";

type Tone = "neutral" | "allow" | "block" | "info" | "warn" | "violet";

const tones: Record<Tone, string> = {
  neutral: "bg-white/5 text-slate-300 ring-white/10",
  allow: "bg-emerald-500/10 text-emerald-300 ring-emerald-400/25",
  block: "bg-rose-500/10 text-rose-300 ring-rose-400/25",
  info: "bg-sky-500/10 text-sky-300 ring-sky-400/25",
  warn: "bg-amber-500/10 text-amber-300 ring-amber-400/25",
  violet: "bg-indigo-500/10 text-indigo-300 ring-indigo-400/25",
};

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Section({
  id,
  eyebrow,
  title,
  lede,
  children,
}: {
  id: string;
  eyebrow: string;
  title: string;
  lede?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section id={id} className="mx-auto max-w-6xl px-5 py-14 sm:px-8">
      <p className="text-xs font-semibold tracking-[0.18em] text-indigo-300/80 uppercase">
        {eyebrow}
      </p>
      <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">{title}</h2>
      {lede ? (
        <p className="mt-3 max-w-3xl text-[15px] leading-relaxed text-slate-400">{lede}</p>
      ) : null}
      <div className="mt-8">{children}</div>
    </section>
  );
}

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <code className={`font-mono text-[12px] text-slate-400 ${className}`}>{children}</code>;
}

export function Dot({ ok }: { ok: boolean }) {
  return (
    <span
      aria-hidden
      className={`inline-block size-1.5 rounded-full ${ok ? "bg-emerald-400 shadow-[0_0_8px] shadow-emerald-400/60" : "bg-rose-400 shadow-[0_0_8px] shadow-rose-400/60"}`}
    />
  );
}
