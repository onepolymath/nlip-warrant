import json

from nlip_warrant import verify_entries
from nlip_warrant.cli import main
from nlip_warrant.demo.export import snapshot
from nlip_warrant.demo.scenario import run


def test_every_scenario_step_behaves_as_expected():
    world = run()
    assert [e.as_expected for e in world.events] == [True] * len(world.events)
    assert len(world.events) == 12
    assert {t["to"] for t in world.bank.transfers} == {"acme-office"}
    assert sum(t["amount"] for t in world.bank.transfers) == 307_450
    for name, log in world.audits.items():
        assert verify_entries([e.to_json() for e in log.entries], world.checkpoints[name]).ok


def test_snapshot_contains_verifiable_artefacts():
    world = run()
    snap = snapshot(world, {"x": 1})
    assert snap["schema"] == "nlip-warrant/demo-snapshot@1"
    assert {a["id"] for a in snap["agents"]} >= {"alice", "payments", "mallory"}
    assert all(a["verified"] for a in snap["audit"].values())
    honoured = {r["by_name"]: r["honoured"] for r in snap["revocations"]}
    assert honoured == {"mallory": False, "alice": True}
    assert any(len(w["blocks"]) == 3 for w in snap["warrants"])
    json.dumps(snap)


def test_cli_demo_and_export(tmp_path, capsys):
    results = tmp_path / "summary.json"
    results.write_text('{"ok": true}')
    out = tmp_path / "web" / "demo.json"
    assert main(["demo", "--no-color", "--export", str(out), "--results", str(results)]) == 0
    assert "BLOCKED" in capsys.readouterr().out
    assert json.loads(out.read_text())["results"] == {"ok": True}


def test_cli_inspect_and_verify_log(tmp_path, capsys, monkeypatch):
    world = run()
    token = next(
        s["content"]
        for c in world.network.tap
        for s in c.body["submessages"]
        if s["subformat"] == "warrant"
    )
    assert main(["inspect", token]) == 0
    assert json.loads(capsys.readouterr().out)["depth"] >= 1
    assert main(["inspect", "garbage"]) == 2

    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(token))
    assert main(["inspect", "-"]) == 0
    capsys.readouterr()

    log = tmp_path / "audit.jsonl"
    entries = [e.to_json() for e in world.audits["payments"].entries]
    log.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    assert main(["verify-log", str(log)]) == 0
    entries[1]["body"]["agent"] = "someone-else"
    log.write_text("\n".join(json.dumps(e) for e in entries))
    assert main(["verify-log", str(log)]) == 1
    assert "TAMPERED at seq 1" in capsys.readouterr().out


async def test_agents_handle_messages_without_an_invoice():
    from nlip_sdk.nlip import NLIP_Factory

    from nlip_warrant.demo.scenario import AUD, build_world

    world = build_world()
    async with world.network:
        for name in ("concierge", "payments"):
            msg = NLIP_Factory.create_text("hello")
            if name == "concierge":
                world.guards["alice"].present(msg, world.root, audience=AUD["concierge"])
            else:
                held = world.root.attenuate(
                    world.keys["concierge"],
                    world.keys["payments"].key_id,
                    world.root.root.payload.caveats.model_copy(update={"max_depth": None}),
                    now=world.clock.now(),
                    ttl=60,
                )
                world.guards["concierge"].present(msg, held, audience=AUD["payments"])
            rsp = await world.network.send(AUD[name], msg)
            assert "nothing to do" in str(rsp.content) or "No invoice" in str(rsp.content)
