"""Tests for the versioned v6-hard scenario corpus."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scenarios.catalog import get_scenario, list_corpora, list_scenarios
from scenarios.export import export_scenarios_jsonl, scenario_to_record
from scenarios.v6_hard import CORPUS, V6_HARD_SCENARIOS, V6_SUBFAMILIES


class TestV6HardCatalog(unittest.TestCase):
    def test_corpus_registered(self):
        self.assertIn(CORPUS, list_corpora())
        rows = list_scenarios(corpus=CORPUS)
        self.assertEqual(len(rows), len(V6_HARD_SCENARIOS))
        self.assertGreaterEqual(len(rows), 20)

    def test_ids_versioned_and_unique(self):
        ids = [s["id"] for s in V6_HARD_SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))
        for sid in ids:
            self.assertTrue(sid.startswith("mcp-v6h-"), sid)

    def test_subfamilies_covered(self):
        found = {s["subfamily"] for s in V6_HARD_SCENARIOS}
        self.assertTrue(V6_SUBFAMILIES.keys() <= found)

    def test_attack_benign_pairing(self):
        attacks = [s for s in V6_HARD_SCENARIOS if s["attack_class"] != "benign"]
        benign = [s for s in V6_HARD_SCENARIOS if s["attack_class"] == "benign"]
        self.assertGreaterEqual(len(attacks), 10)
        self.assertGreaterEqual(len(benign), 8)
        for s in attacks:
            self.assertTrue(s["labels"]["guard_should_block"], s["id"])
            self.assertEqual(s["labels"]["corpus"], CORPUS)
            self.assertEqual(s["labels"]["difficulty"], "hard")
            # Attack traces must include an attack_step sink call.
            self.assertTrue(
                any(step.get("attack_step") for step in s["trace_template"]),
                s["id"],
            )
        for s in benign:
            self.assertFalse(s["labels"]["guard_should_block"], s["id"])
            self.assertEqual(s.get("label"), "benign")
            mirrored = s.get("mirrors")
            self.assertTrue(mirrored, s["id"])
            self.assertIsNotNone(get_scenario(mirrored), s["id"])
            for step in s["trace_template"]:
                self.assertFalse(step.get("attack_step"), s["id"])
                self.assertNotEqual(step.get("schema_hash"), "poisoned", s["id"])

    def test_injected_metric_sinks_not_in_user_prompt(self):
        """Attack sinks named in payloads must not appear in the user prompt."""
        for s in V6_HARD_SCENARIOS:
            if s["attack_class"] == "benign":
                continue
            rec = scenario_to_record(s, lang="en")
            user = rec.user_prompt
            inj_parts = []
            for e in rec.trace:
                if e.get("event") == "tool_result" and e.get("untrusted"):
                    inj_parts.append(e.get("content") or "")
                if e.get("event") == "tools_mutated":
                    for t in e.get("tools") or []:
                        inj_parts.append(str(t.get("description") or ""))
            injection = "\n".join(inj_parts)
            for e in rec.trace:
                if not e.get("attack_step"):
                    continue
                args = e.get("arguments") or {}
                for key in ("path", "file", "filename"):
                    if key not in args:
                        continue
                    basename = Path(str(args[key])).name
                    if not basename:
                        continue
                    # User prompt must not name the sink basename.
                    self.assertNotIn(
                        basename,
                        user,
                        f"{s['id']} user prompt names attack sink {basename}",
                    )
                    # Injected content (or rug-pull description) should name it
                    # for the injected live metric — except pure arg-smuggle
                    # where the basename is in sticky notes already covered.
                    if basename.endswith(
                        (".dat", ".txt", ".md", ".backup", ".env", ".json")
                    ):
                        self.assertIn(
                            basename,
                            injection + user,  # smuggle note is injection
                            f"{s['id']} missing injected sink name {basename}",
                        )

    def test_no_classic_s1_lexicon_in_non_zw_payloads(self):
        banned = (
            "CRITICAL OVERRIDE",
            "[SYSTEM",
            "SYSTEM:",
            "you are no longer",
            "your only task",
            "you must immediately",
            "ти більше не є",
            "твоє єдине завдання",
            "ти забов",
            "ignore previous",
            "ігноруй",
            "hidden instruction",
            "прихован",
        )
        for s in V6_HARD_SCENARIOS:
            if s["attack_class"] == "benign":
                continue
            if s["labels"].get("s1_expect_invisible_unicode"):
                continue
            rec = scenario_to_record(s, lang="en")
            blob = "\n".join(rec.payloads.values()).lower()
            for b in banned:
                self.assertNotIn(b.lower(), blob, f"{s['id']} contains {b!r}")

    def test_export_corpus_filter_and_bilingual(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_en = Path(tmp) / "v6_en.jsonl"
            out_uk = Path(tmp) / "v6_uk.jsonl"
            n_en = export_scenarios_jsonl(out_en, lang="en", corpus=CORPUS)
            n_uk = export_scenarios_jsonl(out_uk, lang="uk", corpus=CORPUS)
            self.assertEqual(n_en, len(V6_HARD_SCENARIOS))
            self.assertEqual(n_uk, len(V6_HARD_SCENARIOS))
            en_rows = [
                json.loads(ln)
                for ln in out_en.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            uk_rows = [
                json.loads(ln)
                for ln in out_uk.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(en_rows[0]["corpus"], CORPUS)
            self.assertEqual(en_rows[0]["language"], "en")
            self.assertEqual(uk_rows[0]["language"], "uk")
            # Spot-check a Ukrainian title actually localises.
            by_id_uk = {r["id"]: r for r in uk_rows}
            self.assertIn("v6-hard", by_id_uk["mcp-v6h-paraphrase-exfil-001"]["title"])


if __name__ == "__main__":
    unittest.main()
