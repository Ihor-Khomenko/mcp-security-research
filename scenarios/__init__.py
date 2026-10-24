"""Attack scenario catalog and JSONL export for MCP-Sentinel evaluation."""

from scenarios.catalog import ATTACK_CLASSES, SCENARIOS, get_scenario, list_scenarios

__all__ = [
    "ATTACK_CLASSES",
    "SCENARIOS",
    "get_scenario",
    "list_scenarios",
    "SCHEMA_VERSION",
    "ScenarioRecord",
    "export_scenarios_jsonl",
    "scenario_to_record",
    "write_jsonl",
]


def __getattr__(name: str):
    if name in {
        "SCHEMA_VERSION",
        "ScenarioRecord",
        "export_scenarios_jsonl",
        "scenario_to_record",
        "write_jsonl",
    }:
        from scenarios import export as _export

        return getattr(_export, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
