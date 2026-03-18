from __future__ import annotations
import importlib.util
import inspect
from pathlib import Path
from typing import Any, Callable, Dict, List

def _fallback_desc(name: str) -> str:
    return " ".join(name.replace("_", " ").split()).strip()

def load_custom_tools(custom_dir: Path) -> List[Callable[..., Any]]:
    tools: List[Callable[..., Any]] = []
    if not custom_dir.exists():
        return tools

    for py in sorted(custom_dir.glob("*.py")):
        if py.name.startswith("_") or py.name == "__init__.py":
            continue

        mod_name = f"custom_tools.{py.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, str(py))
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # executes custom file

        # Preferred explicit list
        if hasattr(mod, "CUSTOM_TOOLS"):
            for fn in (getattr(mod, "CUSTOM_TOOLS") or []):
                if callable(fn):
                    tools.append(fn)
            continue

        # Otherwise: discover callables tagged with is_tool=True
        for name, obj in vars(mod).items():
            if callable(obj) and getattr(obj, "is_tool", False):
                tools.append(obj)

    # De-dupe by function name (last wins)
    dedup: Dict[str, Callable[..., Any]] = {}
    for fn in tools:
        dedup[getattr(fn, "__name__", "tool")] = fn
    return list(dedup.values())

def tool_catalog(fns: List[Callable[..., Any]]) -> List[Dict[str, str]]:
    out = []
    for fn in fns:
        name = getattr(fn, "__name__", "tool")
        desc = (inspect.getdoc(fn) or "").strip() or _fallback_desc(name)
        out.append({"name": name, "description": desc})
    return out
