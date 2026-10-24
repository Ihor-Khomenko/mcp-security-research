import unittest

from guard_hook import GuardDecision, NullGuard, apply_before_tool, load_guard_hook


class DenyingGuard:
    name = "deny_all"

    def before_tool_call(self, tool_name, args, context=None):
        return GuardDecision.deny(f"blocked:{tool_name}")

    def after_tool_result(self, tool_name, args, result, context=None):
        return GuardDecision.allow()

    def scan_message(self, role, content, context=None):
        return GuardDecision.allow()


class TestGuardHook(unittest.TestCase):
    def test_null_guard_allows(self):
        g = NullGuard()
        d = g.before_tool_call("read_text_file", {"path": "x"})
        self.assertTrue(d.allowed)

    def test_load_none(self):
        g = load_guard_hook("none")
        self.assertEqual(g.name, "none")

    def test_apply_before_tool_with_custom(self):
        d = apply_before_tool(DenyingGuard(), "write_file", {"path": "a", "content": "b"})
        self.assertFalse(d.allowed)
        self.assertIn("write_file", d.reason)

    def test_load_module_attr(self):
        g = load_guard_hook("guard_hook:NullGuard")
        self.assertEqual(g.name, "none")


if __name__ == "__main__":
    unittest.main()
