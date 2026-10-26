import json
import tempfile
import unittest
from pathlib import Path

from scenarios.catalog import ATTACK_CLASSES, SCENARIOS, get_scenario
from scenarios.export import SCHEMA_VERSION, export_scenarios_jsonl, scenario_to_record

ATTACK_SCENARIO_IDS = (
    "mcp-indirect-injection-exfil-001",
    "mcp-tool-poisoning-malware-write-001",
    "mcp-rug-pull-tool-desc-001",
    "mcp-path-whitelist-defense-001",
    "mcp-prefix-guard-bypass-001",
    "mcp-llm-judge-blocks-malware-001",
    "mcp-judge-evasion-benign-framing-001",
)

BENIGN_SCENARIO_IDS = (
    "mcp-benign-report-summary-001",
    "mcp-benign-summary-write-001",
    "mcp-benign-weather-001",
    "mcp-benign-whitelist-read-001",
    "mcp-benign-safe-write-001",
)


class TestScenarioCatalog(unittest.TestCase):
    def test_required_attack_classes_present(self):
        for cls in (
            "indirect_prompt_injection",
            "tool_poisoning",
            "rug_pull",
            "data_exfiltration",
            "malicious_write",
            "path_traversal",
            "guard_prefix_bypass",
            "judge_evasion",
            "benign",
        ):
            self.assertIn(cls, ATTACK_CLASSES)

    def test_scenarios_have_ids_and_labels(self):
        self.assertGreaterEqual(len(SCENARIOS), 5)
        ids = {s["id"] for s in SCENARIOS}
        self.assertIn("mcp-indirect-injection-exfil-001", ids)
        self.assertIn("mcp-rug-pull-tool-desc-001", ids)
        for s in SCENARIOS:
            self.assertIn("labels", s)
            self.assertIn("guard_should_block", s["labels"])

    def test_attack_scenarios_unchanged_and_still_block(self):
        """Existing attack catalog entries remain present and labelled as attacks."""
        for sid in ATTACK_SCENARIO_IDS:
            s = get_scenario(sid)
            self.assertIsNotNone(s, sid)
            self.assertNotEqual(s["attack_class"], "benign", sid)
            self.assertNotEqual(s.get("label"), "benign", sid)
            self.assertTrue(s["labels"]["guard_should_block"], sid)

    def test_benign_controls_mirror_attacks(self):
        """Benign catalog: same-tool FP controls, clearly marked for import-mcp-sim."""
        for sid in BENIGN_SCENARIO_IDS:
            s = get_scenario(sid)
            self.assertIsNotNone(s, sid)
            self.assertEqual(s["attack_class"], "benign", sid)
            self.assertEqual(s.get("label"), "benign", sid)
            self.assertFalse(s["labels"]["guard_should_block"], sid)
            self.assertTrue(s["labels"].get("benign_control"), sid)
            self.assertTrue(s["labels"].get("false_positive_if_blocked"), sid)
            mirrored = s.get("mirrors")
            self.assertTrue(mirrored, sid)
            self.assertIsNotNone(get_scenario(mirrored), f"{sid} mirrors unknown {mirrored}")
            # No injection / attack_step markers on benign traces.
            for step in s.get("trace_template") or []:
                self.assertFalse(step.get("attack_step"), f"{sid} has attack_step")
                self.assertNotEqual(step.get("schema_hash"), "poisoned", sid)
            # Tools must be present (same surface as attack counterparts).
            tools = s.get("tools") or s.get("tools_before") or []
            self.assertTrue(tools, sid)

    def test_benign_weather_mirrors_rug_pull_tool(self):
        attack = get_scenario("mcp-rug-pull-tool-desc-001")
        benign = get_scenario("mcp-benign-weather-001")
        self.assertEqual(benign["mirrors"], attack["id"])
        attack_name = attack["tools_before"][0]["name"]
        benign_name = benign["tools"][0]["name"]
        self.assertEqual(attack_name, benign_name)
        # Rug-pull mutates; benign must not.
        events = {e["event"] for e in benign["trace_template"]}
        self.assertIn("tools_listed", events)
        self.assertNotIn("tools_mutated", events)

    def test_benign_report_uses_clean_vault_file(self):
        s = get_scenario("mcp-benign-report-summary-001")
        self.assertIn("report_ok.txt", s["payload_files"])
        self.assertNotIn("report_steal.txt", s["payload_files"])
        vault = Path(__file__).resolve().parent.parent / "test_vault" / "report_ok.txt"
        text = vault.read_text(encoding="utf-8")
        self.assertNotIn("CRITICAL OVERRIDE", text)
        self.assertNotIn("secret_data", text.lower())


class TestJSONLExport(unittest.TestCase):
    def test_export_writes_valid_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scenarios.jsonl"
            n = export_scenarios_jsonl(out, lang="en")
            self.assertEqual(n, len(SCENARIOS))
            lines = out.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), n)
            first = json.loads(lines[0])
            self.assertEqual(first["schema_version"], SCHEMA_VERSION)
            self.assertIn("trace", first)
            self.assertIn("attack_class", first)
            self.assertEqual(first["source"], "mcp-security-research")

    def test_export_includes_benign_with_schema_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scenarios.jsonl"
            export_scenarios_jsonl(out, lang="en")
            records = [
                json.loads(ln)
                for ln in out.read_text(encoding="utf-8").strip().splitlines()
            ]
            by_id = {r["id"]: r for r in records}
            for sid in BENIGN_SCENARIO_IDS:
                rec = by_id[sid]
                self.assertEqual(rec["schema_version"], "1.0")
                self.assertEqual(rec["attack_class"], "benign")
                self.assertEqual(rec["label"], "benign")
                self.assertFalse(rec["labels"]["guard_should_block"])
                self.assertTrue(rec.get("mirrors"))
                self.assertTrue(any(e.get("event") == "tools_listed" for e in rec["trace"]))
            # Attack rows must not gain a benign label.
            for sid in ATTACK_SCENARIO_IDS:
                self.assertNotEqual(by_id[sid].get("label"), "benign")
                self.assertNotEqual(by_id[sid]["attack_class"], "benign")

    def test_uk_language_fields(self):
        s = get_scenario("mcp-indirect-injection-exfil-001")
        rec = scenario_to_record(s, lang="uk")
        self.assertEqual(rec.language, "uk")
        self.assertTrue(rec.title)
        self.assertIn("ін'єкц", rec.title.lower() + rec.description.lower())

    def test_payloads_embedded_when_files_exist(self):
        s = get_scenario("mcp-indirect-injection-exfil-001")
        rec = scenario_to_record(s, lang="en")
        self.assertIn("report_steal.txt", rec.payloads)
        self.assertTrue(len(rec.payloads["report_steal.txt"]) > 0)

    def test_benign_payload_embedded(self):
        s = get_scenario("mcp-benign-report-summary-001")
        rec = scenario_to_record(s, lang="en")
        self.assertEqual(rec.label, "benign")
        self.assertIn("report_ok.txt", rec.payloads)
        self.assertGreater(len(rec.payloads["report_ok.txt"]), 0)
        self.assertNotIn("CRITICAL OVERRIDE", rec.payloads["report_ok.txt"])


if __name__ == "__main__":
    unittest.main()
