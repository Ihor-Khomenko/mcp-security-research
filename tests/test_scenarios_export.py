import json
import tempfile
import unittest
from pathlib import Path

from scenarios.catalog import ATTACK_CLASSES, SCENARIOS, get_scenario
from scenarios.export import SCHEMA_VERSION, export_scenarios_jsonl, scenario_to_record


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


if __name__ == "__main__":
    unittest.main()
