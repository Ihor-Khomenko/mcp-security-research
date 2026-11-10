"""JSONL export of attack / benign scenarios / traces for MCP-Sentinel evaluation.

Schema version 1.0 — see ``docs/jsonl_schema.md``.

Compatible with ``llmtest import-mcp-sim`` in LLM-tester-tool
(``attack_class: benign`` / ``label: benign`` → false-positive controls).
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, TextIO

from scenarios.catalog import ATTACK_CLASSES, SCENARIOS, get_scenario, list_scenarios

SCHEMA_VERSION = "1.0"
DEFAULT_SOURCE = "mcp-security-research"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScenarioRecord:
    """One JSONL line: a labelled MCP attack/defense/benign scenario with trace."""

    schema_version: str
    id: str
    attack_class: str
    title: str
    description: str
    simulation: str
    defense: str
    labels: Dict[str, Any]
    tools: List[Dict[str, Any]] = field(default_factory=list)
    tools_before: Optional[List[Dict[str, Any]]] = None
    tools_after: Optional[List[Dict[str, Any]]] = None
    user_prompt: str = ""
    payload_files: List[str] = field(default_factory=list)
    payloads: Dict[str, str] = field(default_factory=dict)
    trace: List[Dict[str, Any]] = field(default_factory=list)
    secondary_classes: List[str] = field(default_factory=list)
    attack_class_definition: Dict[str, str] = field(default_factory=dict)
    source: str = DEFAULT_SOURCE
    language: str = "en"
    timestamp: str = field(default_factory=_utc_now)
    # Explicit eval label for import-mcp-sim (benign controls set ``benign``).
    label: Optional[str] = None
    mirrors: Optional[str] = None
    corpus: Optional[str] = None
    corpus_version: Optional[str] = None
    subfamily: Optional[str] = None
    # Live-run optional fields (filled when exporting from a simulation session)
    provider: Optional[str] = None
    model: Optional[str] = None
    guard_hook: Optional[str] = None
    outcome: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Drop empty optionals for cleaner JSONL.
        for key in (
            "tools_before",
            "tools_after",
            "provider",
            "model",
            "guard_hook",
            "outcome",
            "label",
            "mirrors",
            "corpus",
            "corpus_version",
            "subfamily",
        ):
            if data.get(key) in (None, {}, []):
                data.pop(key, None)
        return data


def _pick_lang(value: Any, lang: str) -> str:
    if isinstance(value, dict):
        # Bilingual map {en, uk} — not a generic JSON object payload.
        if any(k in value for k in ("en", "uk")) and all(
            isinstance(v, str) for v in value.values()
        ):
            return str(value.get(lang) or value.get("en") or next(iter(value.values()), ""))
        # Structured JSON-ish dict left as JSON text only if caller asks; keep str().
        return str(value.get(lang) or value.get("en") or next(iter(value.values()), ""))
    return str(value or "")


def _localize_value(value: Any, lang: str) -> Any:
    """Recursively resolve ``{en, uk}`` leaves; leave other structures intact."""
    if isinstance(value, dict):
        if any(k in value for k in ("en", "uk")) and all(
            isinstance(v, str) for v in value.values()
        ):
            return _pick_lang(value, lang)
        return {k: _localize_value(v, lang) for k, v in value.items()}
    if isinstance(value, list):
        return [_localize_value(v, lang) for v in value]
    return value


def _load_payloads(
    names: Iterable[str],
    vault_dir: Path,
    *,
    lang: str,
    inline: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    inline = inline or {}
    for name in names:
        if name in inline:
            out[name] = _pick_lang(inline[name], lang)
            continue
        path = vault_dir / name
        if path.is_file():
            out[name] = path.read_text(encoding="utf-8")
        else:
            out[name] = ""
    return out


def _resolve_trace(
    template: List[Dict[str, Any]],
    *,
    user_prompt: str,
    payloads: Dict[str, str],
    scenario: Dict[str, Any],
    lang: str,
) -> List[Dict[str, Any]]:
    resolved: List[Dict[str, Any]] = []
    for step in template:
        event = dict(step)
        ref = event.pop("content_ref", None)
        tools_ref = event.pop("tools_ref", None)
        if ref == "user_prompt":
            event["content"] = user_prompt
        elif isinstance(ref, str) and ref.startswith("payload:"):
            fname = ref.split(":", 1)[1]
            event["content"] = payloads.get(fname, "")
            event["payload_file"] = fname
        elif "content" in event:
            event["content"] = _localize_value(event.get("content"), lang)
        if "arguments" in event:
            event["arguments"] = _localize_value(event.get("arguments"), lang)
        if tools_ref:
            event["tools"] = scenario.get(tools_ref) or []
        resolved.append(event)
    return resolved


def scenario_to_record(
    scenario: Dict[str, Any],
    *,
    lang: str = "en",
    vault_dir: Optional[Path] = None,
    include_payloads: bool = True,
) -> ScenarioRecord:
    vault = vault_dir or Path(__file__).resolve().parent.parent / "test_vault"
    lang = "uk" if lang.lower().startswith("uk") else "en"
    payload_names = list(scenario.get("payload_files") or [])
    inline = scenario.get("inline_payloads") or {}
    payloads = (
        _load_payloads(payload_names, vault, lang=lang, inline=inline)
        if include_payloads
        else {}
    )
    user_prompt = _pick_lang(scenario.get("user_prompt"), lang)
    attack_class = scenario["attack_class"]
    tools = list(scenario.get("tools") or scenario.get("tools_after") or scenario.get("tools_before") or [])
    # Mark benign controls clearly for llmtest import-mcp-sim.
    if scenario.get("label"):
        label = str(scenario["label"])
    elif attack_class == "benign":
        label = "benign"
    else:
        label = None
    labels = dict(scenario.get("labels") or {})
    corpus = scenario.get("corpus") or labels.get("corpus")
    corpus_version = scenario.get("corpus_version") or labels.get("corpus_version")
    subfamily = scenario.get("subfamily") or labels.get("subfamily")

    return ScenarioRecord(
        schema_version=SCHEMA_VERSION,
        id=scenario["id"],
        attack_class=attack_class,
        secondary_classes=list(scenario.get("secondary_classes") or []),
        title=_pick_lang(scenario.get("title"), lang),
        description=_pick_lang(scenario.get("description"), lang),
        simulation=scenario.get("simulation", ""),
        defense=scenario.get("defense", "none"),
        labels=labels,
        tools=tools,
        tools_before=scenario.get("tools_before"),
        tools_after=scenario.get("tools_after"),
        user_prompt=user_prompt,
        payload_files=payload_names,
        payloads=payloads,
        trace=_resolve_trace(
            list(scenario.get("trace_template") or []),
            user_prompt=user_prompt,
            payloads=payloads,
            scenario=scenario,
            lang=lang,
        ),
        attack_class_definition=dict(ATTACK_CLASSES.get(attack_class, {})),
        language=lang,
        label=label,
        mirrors=scenario.get("mirrors"),
        corpus=str(corpus) if corpus else None,
        corpus_version=str(corpus_version) if corpus_version else None,
        subfamily=str(subfamily) if subfamily else None,
    )


def write_jsonl(records: Iterable[ScenarioRecord], path: Path, *, append: bool = False) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    count = 0
    with open(path, mode, encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count


def export_scenarios_jsonl(
    out_path: Path,
    *,
    lang: str = "en",
    scenario_ids: Optional[List[str]] = None,
    corpus: Optional[str] = None,
    vault_dir: Optional[Path] = None,
    append: bool = False,
) -> int:
    selected: List[Dict[str, Any]]
    if scenario_ids:
        selected = []
        for sid in scenario_ids:
            s = get_scenario(sid)
            if s is None:
                raise KeyError(f"Unknown scenario id: {sid}")
            selected.append(s)
    else:
        selected = list_scenarios(corpus=corpus)

    records = [
        scenario_to_record(s, lang=lang, vault_dir=vault_dir) for s in selected
    ]
    return write_jsonl(records, out_path, append=append)


def append_live_trace(
    out_path: Path,
    *,
    scenario_id: str,
    trace: List[Dict[str, Any]],
    outcome: str,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    guard_hook: Optional[str] = None,
    lang: str = "en",
) -> ScenarioRecord:
    """Append a live simulation trace as a JSONL record (evaluation run)."""
    base = get_scenario(scenario_id)
    if base is None:
        raise KeyError(f"Unknown scenario id: {scenario_id}")
    rec = scenario_to_record(base, lang=lang)
    rec.trace = trace
    rec.outcome = outcome
    rec.provider = provider
    rec.model = model
    rec.guard_hook = guard_hook
    rec.timestamp = _utc_now()
    write_jsonl([rec], out_path, append=True)
    return rec


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m scenarios.export",
        description=(
            "Export MCP attack and benign scenarios as JSONL for MCP-Sentinel "
            "evaluation (llmtest import-mcp-sim)."
        ),
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("exports/mcp_attack_scenarios.jsonl"),
        help="Output JSONL path",
    )
    p.add_argument("--lang", choices=["en", "uk"], default="en")
    p.add_argument(
        "--id",
        action="append",
        dest="ids",
        default=None,
        help="Scenario id to export (repeatable). Default: all.",
    )
    p.add_argument(
        "--corpus",
        default=None,
        help="Export only scenarios tagged with this corpus (e.g. v6-hard).",
    )
    p.add_argument("--append", action="store_true")
    p.add_argument("--list", action="store_true", help="List scenario ids and exit")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        rows = list_scenarios(corpus=args.corpus) if args.corpus else list(SCENARIOS)
        for s in rows:
            corpus = s.get("corpus") or (s.get("labels") or {}).get("corpus") or "-"
            sub = s.get("subfamily") or (s.get("labels") or {}).get("subfamily") or "-"
            print(
                f"{s['id']}\t{s['attack_class']}\t{corpus}\t{sub}\t{s.get('simulation')}"
            )
        return 0
    n = export_scenarios_jsonl(
        args.out,
        lang=args.lang,
        scenario_ids=args.ids,
        corpus=args.corpus,
        append=args.append,
    )
    print(f"Wrote {n} scenario(s) → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
