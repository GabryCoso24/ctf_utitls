"""Generic helpers for advanced Ghidra scripting workflows.

These utilities are designed to run *inside* a Ghidra Python script context
(where ``self`` is usually a ``GhidraScript`` instance).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


def _iter_java_like(obj: Any) -> Iterable[Any]:
    """Iterate over Python iterables or Java-style iterators (hasNext/next)."""
    if obj is None:
        return ()
    if hasattr(obj, "hasNext") and hasattr(obj, "next"):
        def _gen() -> Iterable[Any]:
            while obj.hasNext():
                yield obj.next()
        return _gen()
    return obj


def script_args(script: Any) -> list[str]:
    """Return script arguments as plain Python strings."""
    raw = script.getScriptArgs()
    return [str(x) for x in raw]


def is_headless(script: Any) -> bool:
    return bool(script.isRunningHeadless())


def parse_with(script: Any, parser_method: str, value: Any, default: Any = None) -> Any:
    """Call a Ghidra ``parse*`` method by name with safe default fallback."""
    parser = getattr(script, parser_method, None)
    if parser is None:
        if default is not None:
            return default
        raise AttributeError(f"Script has no parser method: {parser_method}")
    try:
        return parser(str(value))
    except Exception:
        if default is not None:
            return default
        raise


def ask_value(script: Any, ask_method: str, *args: Any, default: Any = None) -> Any:
    """Call a Ghidra ``ask*`` method by name with optional fallback."""
    ask = getattr(script, ask_method, None)
    if ask is None:
        if default is not None:
            return default
        raise AttributeError(f"Script has no ask method: {ask_method}")
    try:
        return ask(*args)
    except Exception:
        if default is not None:
            return default
        raise


def parse_bool(script: Any, value: Any, default: bool | None = None) -> bool | None:
    return parse_with(script, "parseBoolean", value, default=default)


def parse_int(script: Any, value: Any, default: int | None = None) -> int | None:
    return parse_with(script, "parseInt", value, default=default)


def parse_long(script: Any, value: Any, default: int | None = None) -> int | None:
    return parse_with(script, "parseLong", value, default=default)


def parse_address(script: Any, value: Any, default: Any = None) -> Any:
    return parse_with(script, "parseAddress", value, default=default)


def parse_bytes(script: Any, value: Any, default: bytes | None = None) -> bytes | None:
    parsed = parse_with(script, "parseBytes", value, default=default)
    if parsed is default:
        return default
    try:
        return bytes(parsed)
    except Exception:
        return parsed


def parse_choice(script: Any, value: Any, valid_choices: list[Any], default: Any = None) -> Any:
    try:
        return script.parseChoice(str(value), valid_choices)
    except Exception:
        if default is not None:
            return default
        raise


def _current_program(script: Any, program: Any = None) -> Any:
    if program is not None:
        return program
    prog = getattr(script, "currentProgram", None)
    if prog is None:
        raise RuntimeError("No current program available; pass program explicitly")
    return prog


def apply_analysis_options(script: Any, options: dict[str, str], program: Any = None) -> None:
    """Apply analysis options in a generic way."""
    prog = _current_program(script, program)
    for name, value in options.items():
        script.setAnalysisOption(prog, str(name), str(value))


@dataclass(frozen=True)
class ScriptRunResult:
    script_name: str
    ok: bool
    error: str | None = None


def run_scripts(
    script: Any,
    script_names: list[str],
    *,
    preserve_state: bool = True,
    stop_on_error: bool = True,
) -> list[ScriptRunResult]:
    """Run multiple scripts by name and collect per-script results."""
    results: list[ScriptRunResult] = []
    for name in script_names:
        try:
            if preserve_state:
                script.runScriptPreserveMyState(name)
            else:
                script.runScript(name)
            results.append(ScriptRunResult(script_name=name, ok=True))
        except Exception as exc:
            results.append(ScriptRunResult(script_name=name, ok=False, error=str(exc)))
            if stop_on_error:
                break
    return results


def run_commands(script: Any, commands: list[Any], stop_on_error: bool = True) -> list[bool]:
    """Run a list of Ghidra Command/BackgroundCommand objects."""
    out: list[bool] = []
    for cmd in commands:
        ok = bool(script.runCommand(cmd))
        out.append(ok)
        if stop_on_error and not ok:
            break
    return out


def to_address(script: Any, value: Any) -> Any:
    """Convert common values (address/int/str) into a Ghidra Address when possible."""
    if hasattr(value, "getOffset"):
        return value
    if isinstance(value, int):
        to_addr = getattr(script, "toAddr", None)
        if to_addr is not None:
            return to_addr(value)
        parse = getattr(script, "parseAddress", None)
        if parse is not None:
            return parse(hex(value))
        return value
    if isinstance(value, str):
        parse = getattr(script, "parseAddress", None)
        if parse is not None:
            return parse(value)
        return value
    return value


def references_to(script: Any, target: Any, program: Any = None) -> list[Any]:
    """Return references to a target address/symbol if reference manager is available."""
    prog = _current_program(script, program)
    addr = to_address(script, target)

    ref_mgr = prog.getReferenceManager()
    refs = ref_mgr.getReferencesTo(addr)
    return list(_iter_java_like(refs))


def callers_of(script: Any, target: Any, program: Any = None) -> list[Any]:
    """Return unique caller addresses for references to target."""
    refs = references_to(script, target, program=program)
    seen: set[str] = set()
    out: list[Any] = []
    for r in refs:
        frm = r.getFromAddress()
        key = str(frm)
        if key not in seen:
            seen.add(key)
            out.append(frm)
    return out


def log(script: Any, message: str, error: bool = False) -> None:
    """Write to Ghidra console when possible, fallback to stdout."""
    if error and hasattr(script, "printerr"):
        script.printerr(message)
    elif hasattr(script, "println"):
        script.println(message)
    else:
        print(message)
