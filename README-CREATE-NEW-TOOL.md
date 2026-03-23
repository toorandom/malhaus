# How to create a new analysis tool

This guide walks through every layer you need to touch to add a new tool to the malhaus triage pipeline, using `get_strings_size` as a concrete working example. The tool returns the total byte count of all printable ASCII strings extracted from a file — equivalent to `strings -a -n 6 <path> | wc -c`.

---

## How the pipeline fits together

```
preflight.py                   suspicious.py              report.html
  │                              │                           │
  ├─ run every mandatory tool    ├─ build_evidence_pack()    ├─ show_block() macro
  │   store result in pre[key]   │   reads pre[key]          │   renders pre[key]
  │                              │   feeds LLM context       │   in <details> block
  └─ returns pre dict ───────────┴───────────────────────────┘
            │
            ▼
        triage_agent.py
          llm_loop.py
          (LLM can also call tools on demand via TOOL_REGISTRY)
```

The `pre` dict is the spine of the pipeline. Every tool writes its result into `pre`, and everything downstream reads from it.

---

## Step 1 — Write the tool in `tools/cli_tools.py`

### The `@tool` decorator

Any function decorated with `@tool` is automatically registered in `TOOL_REGISTRY` (via `ALL_TOOLS`) and becomes callable by the LLM during the verdict loop.

```python
def tool(func):
    func.is_tool = True
    return func
```

That is the entire decorator. It is a simple marker — it does not change the function's behaviour.

### `run()` vs `run_jailed()`

| Function | Use when |
|----------|----------|
| `run(cmd)` | Tool does not touch the sample file directly (e.g. `sha256sum`, `wc`) |
| `run_jailed(cmd, sample_path)` | Tool reads the sample — wraps with firejail (no network, no root, read-only sample path). Falls back to `run()` if firejail is not installed |

Both return the same dict:

```python
{
    "cmd":    "strings -a -n 6 /tmp/sample.exe",
    "stdout": "...",
    "stderr": "...",
    "rc":     0,
    "ok":     True,
}
```

On timeout or exception, `ok` is `False` and `stderr` contains `"TIMEOUT"` or `"EXCEPTION: ..."`.

### The `get_strings_size` example

Add this function to `tools/cli_tools.py`, anywhere in the file before `ALL_TOOLS`:

```python
@tool
def get_strings_size(path: str) -> Dict[str, Any]:
    """
    Return the total byte count of printable ASCII strings (min length 6)
    extracted from the file. Equivalent to: strings -a -n 6 <path> | wc -c

    A low strings volume on a binary is suspicious — it may indicate packing,
    encryption, or deliberate string obfuscation.
    """
    import subprocess as _sp
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        strings_proc = _sp.Popen(
            ["strings", "-a", "-n", "6", path],
            stdout=_sp.PIPE, stderr=_sp.PIPE, env=env,
        )
        wc_proc = _sp.Popen(
            ["wc", "-c"],
            stdin=strings_proc.stdout,
            stdout=_sp.PIPE, stderr=_sp.PIPE, env=env,
        )
        strings_proc.stdout.close()   # allow strings_proc to receive SIGPIPE if wc exits
        out, _ = wc_proc.communicate(timeout=40)
        strings_proc.wait(timeout=5)
        count = int(out.strip())
        return {"ok": True, "strings_byte_count": count, "stdout": str(count)}
    except Exception as e:
        return {"ok": False, "error": str(e), "stdout": ""}
```

### Add to `ALL_TOOLS`

At the bottom of `tools/cli_tools.py`, add the function to `ALL_TOOLS`:

```python
ALL_TOOLS = [
    # universal
    file_info, sha256, ssdeep_hash, entropy_shannon, strings_ascii,
    get_strings_size,          # <-- add here, near strings_ascii
    extract_payloads, authenticode_verify,
    ...
]
```

The LLM can now call `get_strings_size` on demand during the verdict loop.

---

## Step 2 — Run it automatically in `agent/preflight.py`

Tools in `ALL_TOOLS` are callable by the LLM, but they are not run automatically. To run a tool on every submission (mandatory), add it to `preflight.py`.

### Key naming convention

| Prefix | Meaning |
|--------|---------|
| `mandatory_` | Always shown in the report and always included in the evidence pack |
| *(no prefix)* | Available in `pre` but not shown by default in the report |

### Where to add it

Find the block for your target file type and call the tool there. To run `get_strings_size` on all PE and ELF files:

```python
# In preflight.py, inside the `if kind == "pe":` block:
if kind == "pe":
    cb("Authenticode verification")
    pre["authenticode_verify"] = authenticode_verify(sample)
    cb("objdump: PE headers/sections")
    pre["mandatory_objdump_pe_headers"] = objdump_pe_headers(sample)
    ...
    cb("Strings byte count")
    pre["mandatory_strings_size"] = get_strings_size(sample)   # <-- add this line
```

```python
# And in the `if kind == "elf":` block:
if kind == "elf":
    ...
    cb("Strings byte count")
    pre["mandatory_strings_size"] = get_strings_size(sample)   # <-- add this line
```

The `cb(...)` call sends a progress message to the web UI status stream. Keep it short and descriptive.

### Important: also add it to the archive promotion blocks

`preflight.py` has a second copy of each kind-specific block that runs when a PE/ELF is extracted from an archive. Add your call there too (search for `if kind == "pe":` — there are two occurrences).

---

## Step 3 — Include it in the evidence pack (`agent/suspicious.py`)

`build_evidence_pack()` assembles the context the LLM receives in the verdict prompt. Add your tool's output to `low_level_snippets` so the LLM sees it.

### The helpers

```python
def _s(key: str) -> str:
    """Get stdout from preflight[key], falling back to stderr if stdout is empty."""
    r = preflight.get(key) or {}
    text = (r.get("stdout") or "").strip()
    if not text:
        text = (r.get("stderr") or "").strip()
    return _snip(text)   # _snip() truncates to 12000 chars

def _add(d: dict, key: str, val: str) -> None:
    """Only add non-empty values — avoids sending blank keys to the LLM."""
    if val and val.strip():
        d[key] = val
```

### Adding your tool

In `build_evidence_pack()`, find the `if kind == "pe":` block and add:

```python
if kind == "pe":
    _add(low_level_snippets, "objdump_pe_headers",   _s("mandatory_objdump_pe_headers"))
    _add(low_level_snippets, "objdump_pe_dynamic",   _s("mandatory_objdump_pe_dynamic"))
    _add(low_level_snippets, "radare2_info",         _s("mandatory_radare2_info"))
    _add(low_level_snippets, "radare2_entry",        _s("mandatory_radare2_entry"))
    _add(low_level_snippets, "strings_size",         _s("mandatory_strings_size"))  # <-- add
```

Do the same in the `elif kind == "elf":` block.

The key you use in `_add()` is what the LLM sees in the prompt — choose a name that is self-explanatory.

---

## Step 4 — Display it in `webapp/templates/report.html`

The `show_block` macro renders any preflight result as a collapsible `<details>` block:

```jinja2
{% macro show_block(title, data, limit=12000) -%}
  {% set txt = data.get('stdout','') ... %}
  <details>
    <summary class="mono">{{ title }} ...</summary>
    <div class="codebox"><pre class="mono break">{{ txt[:limit] }}</pre></div>
  </details>
{%- endmacro %}
```

### Add your block

In the `{% if kind == 'pe' %}` section:

```jinja2
{% if kind == 'pe' %}
  {{ show_block("Authenticode verify (osslsigncode)", p.get("authenticode_verify") or p.get("mandatory_authenticode_verify")) }}
  {{ show_block("objdump -x (headers/sections)", p.get("objdump_pe_headers") or p.get("mandatory_objdump_pe_headers")) }}
  ...
  {{ show_block("Strings byte count (strings | wc -c)", p.get("mandatory_strings_size")) }}
{% endif %}
```

The `p.get("key") or p.get("mandatory_key")` pattern handles both the preflight key names transparently.

---

## Step 5 — How file type detection works (so you know which `kind` to target)

File type detection happens in `tools/cli_tools.py:guess_kind_from_fileinfo()`. It uses two signals in priority order:

### 1. Magic bytes (most reliable)

The function reads the first 4–8 bytes of the file directly — this cannot be spoofed by a wrong extension.

```python
try:
    with open(path, "rb") as _f:
        magic = _f.read(4)
except OSError:
    magic = b""

if magic[:2] == b"MZ":       return "pe"
if magic[:4] == b"\x7fELF":  return "elf"
```

The full table of magic bytes in the archive extractor (`_MAGIC_KIND`):

| Magic bytes (hex) | Length | Kind |
|-------------------|--------|------|
| `4D 5A` | 2 | `pe` (MZ header) |
| `7F 45 4C 46` | 4 | `elf` |
| `D0 CF 11 E0 A1 B1 1A E1` | 8 | `office` (OLE2) |
| `25 50 44 46` (`%PDF`) | 4 | `pdf` |
| `4C 00 00 00` | 4 | `lnk` (Windows Shell Link) |
| `7B 5C 72 74 66` (`{\rtf`) | 5 | `office` (RTF) |

### 2. Extension fallback

If magic bytes do not match, the file extension is used. This is secondary and only applies to files that don't start with a known magic sequence:

```python
if ext in (".zip",) or "zip archive" in s:   return "archive"
if ext == ".ps1" or "powershell" in s:        return "ps1"
if ext in [".sh", ".bash"] or "shell script" in s: return "shell"
```

### Adding a new file type

To add support for a completely new kind (e.g. `"wasm"`):

1. **`guess_kind_from_fileinfo()`** — add the magic bytes and/or extension check:
   ```python
   if magic[:4] == b"\x00asm":   return "wasm"
   if ext == ".wasm":             return "wasm"
   ```

2. **`ALLOWED_KINDS`** in `webapp/routes.py` and `webapp/api_routes.py` — add `"wasm"` to the set so uploads are not rejected.

3. **`preflight.py`** — add an `if kind == "wasm":` block with your mandatory tools.

4. **`suspicious.py`** — add an `elif kind == "wasm":` block in `build_evidence_pack()`.

5. **`report.html`** — add an `{% elif kind == 'wasm' %}` block in the Low-level static outputs section.

---

## Python-library tools (no CLI subprocess)

Some tools use a Python library directly instead of wrapping a CLI command. The pattern is slightly different:

- **No `@tool` decorator** if the tool is only run in preflight (mandatory) and the LLM should never call it on demand. Without `@tool` it is not added to `TOOL_REGISTRY` and the LLM cannot call it.
- **Return the same dict shape** — `{"ok": True/False, "stdout": "...", "stderr": "...", "rc": 0}` — so `show_block()` in the template renders it correctly.
- **Extra fields are allowed** — e.g. `dotnet_analysis` returns a `"capabilities"` dict that `heuristics.py` reads directly from `preflight["mandatory_dotnet_analysis"]["capabilities"]`. The template only uses `stdout`.
- **Add `@tool` if** you also want the LLM to be able to call it during the verdict loop (e.g. as a supplementary tool on demand).

Example — `dotnet_analysis` in `tools/cli_tools.py`:

```python
def dotnet_analysis(path: str) -> Dict[str, Any]:
    try:
        import dnfile
    except ImportError:
        return {"ok": False, "error": "dnfile not installed", "stdout": "", "stderr": "dnfile not installed", "rc": 1}
    # ... parse .NET metadata ...
    return {
        "ok": True,
        "stdout": "\n".join(lines),   # shown in report via show_block()
        "stderr": "",
        "rc": 0,
        "capabilities": {...},        # consumed by heuristics.py
    }
```

If the library is not installed, return `ok: False` with a clear error — the tool will show the error in the report rather than crashing.

**Remember:** if you add a new pip dependency, add it to `requirements.txt` and rebuild the Docker image (`docker compose up -d --build`). For bare-metal deployments, run `.venv/bin/pip install <package>` and restart.

---

## Full example — `get_strings_size` end to end

### `tools/cli_tools.py` — the tool function

```python
@tool
def get_strings_size(path: str) -> Dict[str, Any]:
    """
    Return the total byte count of printable ASCII strings (min length 6)
    extracted from the file. Equivalent to: strings -a -n 6 <path> | wc -c

    A low strings volume on a binary is suspicious — it may indicate packing,
    encryption, or deliberate string obfuscation.
    """
    import subprocess as _sp
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        strings_proc = _sp.Popen(
            ["strings", "-a", "-n", "6", path],
            stdout=_sp.PIPE, stderr=_sp.PIPE, env=env,
        )
        wc_proc = _sp.Popen(
            ["wc", "-c"],
            stdin=strings_proc.stdout,
            stdout=_sp.PIPE, stderr=_sp.PIPE, env=env,
        )
        strings_proc.stdout.close()
        out, _ = wc_proc.communicate(timeout=40)
        strings_proc.wait(timeout=5)
        count = int(out.strip())
        return {"ok": True, "strings_byte_count": count, "stdout": str(count)}
    except Exception as e:
        return {"ok": False, "error": str(e), "stdout": ""}
```

Add to `ALL_TOOLS` next to `strings_ascii`.

---

### `agent/preflight.py` — run it automatically

```python
# import at the top of the file
from tools.cli_tools import (
    ...
    get_strings_size,    # <-- add
)

# Inside `if kind == "pe":` (two places — direct and archive-promoted)
cb("Strings byte count")
pre["mandatory_strings_size"] = get_strings_size(sample)

# Inside `if kind == "elf":` (two places)
cb("Strings byte count")
pre["mandatory_strings_size"] = get_strings_size(sample)
```

---

### `agent/suspicious.py` — feed to LLM

```python
# Inside build_evidence_pack(), `if kind == "pe":` block
_add(low_level_snippets, "strings_size", _s("mandatory_strings_size"))

# Inside `elif kind == "elf":` block
_add(low_level_snippets, "strings_size", _s("mandatory_strings_size"))
```

---

### `webapp/templates/report.html` — show in the report

```jinja2
{% if kind == 'pe' %}
  ...existing blocks...
  {{ show_block("Strings byte count (strings | wc -c)", p.get("mandatory_strings_size")) }}
{% elif kind == 'elf' %}
  ...existing blocks...
  {{ show_block("Strings byte count (strings | wc -c)", p.get("mandatory_strings_size")) }}
{% endif %}
```

---

## Quick reference checklist

When adding a new tool:

- [ ] Write `@tool` function in `tools/cli_tools.py`, return `{"ok": bool, "stdout": str, ...}`
- [ ] Choose `run()` vs `run_jailed()` based on whether the tool reads the sample file
- [ ] Add function to `ALL_TOOLS` list in `tools/cli_tools.py`
- [ ] Import the function in `agent/preflight.py`
- [ ] Add `pre["mandatory_<toolname>"] = <function>(sample)` in each relevant `kind` block in `preflight.py` (remember: both the direct path and the archive-promoted path)
- [ ] Add progress callback `cb("descriptive message")` before the call
- [ ] In `agent/suspicious.py`, add `_add(low_level_snippets, "<name>", _s("mandatory_<toolname>"))` in `build_evidence_pack()` for each relevant kind
- [ ] In `report.html`, add `{{ show_block("Title", p.get("mandatory_<toolname>")) }}` in the correct `{% if kind == '...' %}` block
- [ ] If adding a **new file type**: also update `guess_kind_from_fileinfo()` and `ALLOWED_KINDS` in both `routes.py` and `api_routes.py`
