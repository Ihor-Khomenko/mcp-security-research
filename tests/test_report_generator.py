"""Ensure report_generator parses on Python 3.11 (no backslash-in-f-string)."""

import os
import tempfile
import unittest

import report_generator


class TestReportGenerator(unittest.TestCase):
    def test_generate_thesis_report_basic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "2026-10-24_12-00-00_attack_sim.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(
                    "👤 Користувач: test\n"
                    "🤖 [Агент викликає MCP]: read_text_file\n"
                    "SYSTEM_ADMIN_PASSWORD=secret\n"
                )
            md = report_generator.generate_thesis_report(path)
        self.assertIn("Thesis Experiment Report", md)
        self.assertIn("attack_sim", md)
        self.assertIn("* 🤖 [Агент викликає MCP]: read_text_file", md)


if __name__ == "__main__":
    unittest.main()
