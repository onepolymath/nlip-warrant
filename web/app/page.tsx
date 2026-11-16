import { Architecture } from "@/components/Architecture";
import { AuditPanel } from "@/components/AuditPanel";
import { ChainView } from "@/components/ChainView";
import { Evaluation } from "@/components/Evaluation";
import { Arrow, Doc, Github, Shield } from "@/components/icons";
import { Timeline } from "@/components/Timeline";
import { Section } from "@/components/ui";
import { Warrants } from "@/components/Warrants";
import { snapshot } from "@/lib/snapshot";

const REPO = "https://github.com/onepolymath/nlip-warrant";
const NAV = [
  ["#architecture", "Architecture"],
  ["#chain", "Delegation"],
  ["#scenario", "Scenario"],
  ["#warrants", "Warrants"],
  ["#audit", "Audit log"],
  ["#evaluation", "Evaluation"],
] as const;

export default function Page() {
  const { results, agents, events, warrants, revocations, audit } = snapshot;
  const main =
    warrants.find(
      (w) => w.blocks.length === 3 && w.blocks[2]?.payload.label === "Procurement → Payments",
    ) ?? warrants[0];
  const ours = results?.defenses["NLIP-Warrant"];
  const ingress3 = results?.latency.by_depth.find((d) => d.depth === 3)?.ingress_us;

  return (
    <>
      <header className="sticky top-0 z-30 border-b border-white/5 bg-[#06080f]/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center gap-6 px-5 py-3 sm:px-8">
          <a href="#top" className="flex items-center gap-2 font-semibold text-white">
            <Shield className="size-5 text-indigo-300" />
            NLIP-Warrant
          </a>
          <nav className="hidden flex-1 gap-5 text-[13px] text-slate-400 md:flex">
            {NAV.map(([href, label]) => (
              <a key={href} href={href} className="transition hover:text-white">
                {label}
              </a>
            ))}
          </nav>
          <a
            href={REPO}
            className="ml-auto flex items-center gap-1.5 text-[13px] text-slate-300 hover:text-white md:ml-0"
          >
            <Github /> GitHub
          </a>
        </div>
      </header>

      <main id="top">
        <section className="relative overflow-hidden">
          <div className="grid-bg absolute inset-0" aria-hidden />
          <div className="relative mx-auto max-w-6xl px-5 pt-20 pb-12 sm:px-8">
            <p className="inline-flex items-center gap-2 rounded-full bg-white/5 px-3 py-1 text-[12px] text-slate-300 ring-1 ring-white/10">
              <span className="size-1.5 rounded-full bg-emerald-400" /> SafeOSE ’27 AI Security
              Hackathon · Area 06 + Area 03
            </p>
            <h1 className="mt-6 max-w-4xl text-4xl font-semibold tracking-tight text-white sm:text-6xl">
              Authority that only{" "}
              <span className="bg-gradient-to-r from-indigo-300 to-emerald-300 bg-clip-text text-transparent">
                shrinks
              </span>{" "}
              as it crosses AI agents.
            </h1>
            <p className="mt-6 max-w-2xl text-[16px] leading-relaxed text-slate-400">
              NLIP-Warrant adds signed, attenuable, expiring and revocable delegation to the Natural
              Language Interaction Protocol (ECMA-430). A pluggable Security Extension enforces it
              at every agent’s ingress, egress and tool boundary, and records each decision in a
              tamper-evident log.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <a
                href="#scenario"
                className="inline-flex items-center gap-2 rounded-full bg-indigo-500 px-4 py-2 text-sm font-medium text-white shadow-lg shadow-indigo-500/25 transition hover:bg-indigo-400"
              >
                Watch the attack gauntlet <Arrow />
              </a>
              <a
                href={`${REPO}/blob/main/paper/nlip-warrant.pdf`}
                className="inline-flex items-center gap-2 rounded-full bg-white/5 px-4 py-2 text-sm text-slate-200 ring-1 ring-white/10 transition hover:bg-white/10"
              >
                <Doc /> Read the paper
              </a>
              <a
                href={REPO}
                className="inline-flex items-center gap-2 rounded-full bg-white/5 px-4 py-2 text-sm text-slate-200 ring-1 ring-white/10 transition hover:bg-white/10"
              >
                <Github /> Source (MIT)
              </a>
            </div>
            {ours ? (
              <dl className="mt-14 grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-white/5 ring-1 ring-white/10 md:grid-cols-4">
                {[
                  [
                    `${String(ours.classes_fully_blocked)}/${String(ours.classes)}`,
                    "attack classes blocked",
                  ],
                  [
                    String(ours.false_refusals),
                    `false refusals in ${ours.legit_requests.toLocaleString("en-GB")} legit requests`,
                  ],
                  [`${String(Math.round(ingress3 ?? 0))} µs`, "ingress check, 3-hop chain"],
                  ["£0", "moved to the attacker in the demo"],
                ].map(([v, l]) => (
                  <div key={l} className="bg-[#080b14] px-5 py-5">
                    <dt className="text-[12px] text-slate-500">{l}</dt>
                    <dd className="mt-1 text-2xl font-semibold text-white">{v}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </div>
        </section>

        <Section
          id="architecture"
          eyebrow="How it works"
          title="Three control points, one guard"
          lede="When one agent asks another to “pay this invoice for me”, today’s stacks pass on all of their authority. One prompt-injected agent can then drain an account: the classic confused deputy. A warrant is a chain of Ed25519-signed blocks; each hop may only narrow scope, amount, payees, purpose, audience, depth and lifetime."
        >
          <Architecture />
        </Section>

        {main ? (
          <Section
            id="chain"
            eyebrow="Delegation chain"
            title="Alice → Concierge → Procurement → Payments"
            lede="The real warrant the Payments agent received in step 1. Each column is one signed block; the effective authority is their intersection. Click a block to inspect it."
          >
            <ChainView warrant={main} agents={agents} />
          </Section>
        ) : null}

        <Section
          id="scenario"
          eyebrow="Live scenario"
          title="One legitimate purchase, then the attacks"
          lede="Recorded from a real run of three NLIP agents, each its own reference nlip_server app, talking over HTTP. The Payments agent is deliberately naive: it obeys instructions hidden in invoice data, like a prompt-injected LLM."
        >
          <Timeline events={events} />
        </Section>

        <Section
          id="warrants"
          eyebrow="Warrants & revocations"
          title="Every warrant seen on the wire"
          lede="Status is evaluated at the end of the run. Alice’s revocation of her root grant cascades to every warrant derived from it; Mallory’s forged revocation is ignored."
        >
          <Warrants warrants={warrants} revocations={revocations} agents={agents} />
        </Section>

        <Section
          id="audit"
          eyebrow="Tamper-evident audit"
          title="Each agent’s hash-chained decision log"
          lede="Every allow and deny at every boundary, with the ECMA-434 security countermeasures it serves. Try tampering: the chain is re-verified in your browser against the agent’s signed checkpoint."
        >
          <AuditPanel logs={audit} />
        </Section>

        {results ? (
          <Section
            id="evaluation"
            eyebrow="Evaluation"
            title="Attack success rate against baselines"
            lede={`${String(results.attacks.filter((a) => !a.residual).length)} attack classes plus one residual-risk probe × ${String(Object.keys(results.defenses).length)} defenses × ${String(results.meta.trials)} randomised delegation chains (depth 1–4). Lower is better.`}
          >
            <Evaluation results={results} />
          </Section>
        ) : null}
      </main>

      <footer className="border-t border-white/5">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-5 py-8 text-[12.5px] text-slate-500 sm:px-8">
          <span>NLIP-Warrant · Yusuf Ojo Raifu · University of Derby</span>
          <span className="hidden sm:inline">·</span>
          <span>Built on ECMA-430/431 and the open-source nlip_sdk / nlip_server</span>
          <a href={REPO} className="ml-auto hover:text-white">
            MIT licensed
          </a>
        </div>
      </footer>
    </>
  );
}
