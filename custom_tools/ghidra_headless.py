import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Tuple
import re
import json


def _java_ok() -> Tuple[bool, str]:
    """
    Ghidra headless requires a recent JDK. We just check 'java -version' works.
    (Your Ghidra build asked for JDK 21+; we don't strictly parse version here.)
    """
    java = shutil.which("java")
    if not java:
        return False, "java not found in PATH (install JDK 21+ and ensure 'java' is available)"
    try:
        p = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=5)
        out = (p.stderr or "") + "\n" + (p.stdout or "")
        return True, out.strip()
    except Exception as e:
        return False, f"java check failed: {e}"


# --- NEW: aggressively filter Ghidra/Java noise so it never pollutes the LLM ---
_DROP_LINE_PATTERNS = [
    r"^Ghidra.*$",
    r"^.*Headless Analyzer.*$",
    r"^.*analyzeHeadless.*$",
    r"^Using log.*$",
    r"^Picked up _JAVA_OPTIONS.*$",
    r"^OpenJDK.*$",
    r"^Java HotSpot.*$",
    r"^WARNING:\s+.*$",
    r"^INFO\s+.*$",
    r"^DEBUG\s+.*$",
    r"^org\.apache\..*$",
    r"^javax\..*$",
    r"^java\..*$",
    r"^\s*Task:\s+.*$",
    r"^\s*\[.*\]\s*$",
]
_DROP_RES = [re.compile(p, re.I) for p in _DROP_LINE_PATTERNS]


def _filter_ghidra_output(s: str, keep_tail: int = 200) -> str:
    """
    Removes typical Ghidra/Java banners, progress, and verbose log lines.
    Keeps only the last `keep_tail` lines of remaining content.
    """
    if not s:
        return ""
    lines = s.splitlines()
    kept = []
    for ln in lines:
        if any(rx.search(ln) for rx in _DROP_RES):
            continue
        # also drop very long single lines (usually classpaths / banners)
        if len(ln) > 5000:
            continue
        kept.append(ln)
    return "\n".join(kept[-keep_tail:])


# --- NEW: write a high-signal JSON report via a Ghidra postScript ---
_EXPORT_SCRIPT_NAME = "ExportTriage.py"


_EXPORT_SCRIPT_CONTENT = r"""# ExportTriage.py
# @category Malhaus
# Exports a compact, high-signal JSON triage report to a path passed as the first arg.

import json, re

def safe(s, limit=400):
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\r"," ").replace("\n"," ")
    return s[:limit]

def main():
    # args: [output_path]
    try:
        out_path = getScriptArgs()[0]
    except:
        out_path = "triage.json"

    prog = currentProgram

    md = {
        "name": safe(prog.getName(), 260),
        "exe_path": safe(prog.getExecutablePath(), 500),
        "lang": safe(prog.getLanguageID()),
        "compiler_spec": safe(prog.getCompilerSpec().getCompilerSpecID()),
        "format": safe(prog.getExecutableFormat()),
        "image_base": safe(prog.getImageBase()),
        "entry": safe(prog.getEntryPoint()),
    }

    # External symbols (imports best-effort)
    ext = []
    symtab = prog.getSymbolTable()
    it = symtab.getExternalSymbols()
    count = 0
    while it.hasNext() and count < 3000:
        s = it.next()
        ext.append({
            "name": safe(s.getName(), 200),
            "address": safe(s.getAddress(), 80),
            "namespace": safe(s.getParentNamespace(), 200),
        })
        count += 1

    sus_re = re.compile(
        r"(VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|"
        r"LoadLibrary|GetProcAddress|WinExec|ShellExecute|URLDownloadToFile|"
        r"Internet(Open|Connect|Read|Write)|Http(Open|Send)|WSAStartup|connect|send|recv|"
        r"Reg(Set|Create|Open)|CreateProcess|Process32(First|Next)|"
        r"Crypt|BCrypt|RtlDecompressBuffer|Nt(Zw)?WriteVirtualMemory|Nt(Zw)?CreateThreadEx)",
        re.I
    )
    sus_imports = sorted({e["name"] for e in ext if sus_re.search(e["name"])})[:400]

    # High-signal strings only
    listing = prog.getListing()
    siter = listing.getDefinedData(True)
    hi = []
    url_re = re.compile(r"https?://", re.I)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    cmd_re = re.compile(r"(powershell|cmd\.exe|rundll32|reg\.exe|wscript|cscript|schtasks|mshta)", re.I)

    scount = 0
    while siter.hasNext() and scount < 200000:
        d = siter.next()
        dt = d.getDataType()
        if dt and dt.getName() == "string":
            val = d.getValue()
            st = safe(val, 500)
            if len(st) >= 6 and (url_re.search(st) or ip_re.search(st) or cmd_re.search(st)):
                hi.append(st)
                if len(hi) >= 250:
                    break
        scount += 1

    # Functions: take top by size
    fm = prog.getFunctionManager()
    funcs = []
    fiter = fm.getFunctions(True)
    while fiter.hasNext() and len(funcs) < 3000:
        f = fiter.next()
        body = f.getBody()
        funcs.append({
            "name": safe(f.getName(), 200),
            "entry": safe(f.getEntryPoint(), 80),
            "size": int(body.getNumAddresses()),
            "is_thunk": bool(f.isThunk()),
        })

    funcs_sorted = sorted(funcs, key=lambda x: x["size"], reverse=True)
    top_funcs = funcs_sorted[:50]

    out = {
        "meta": md,
        "imports_total": len(ext),
        "suspicious_imports": sus_imports,
        "interesting_strings": hi,
        "top_functions": top_funcs,
    }

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

main()
"""


def _ensure_export_script(scripts_dir: Path) -> None:
    """
    Ensure our exporter postScript exists in the scripts dir.
    We write it if missing (or empty). This keeps your deployment copy/paste friendly.
    """
    scripts_dir.mkdir(parents=True, exist_ok=True)
    p = scripts_dir / _EXPORT_SCRIPT_NAME
    if not p.exists() or p.stat().st_size < 50:
        p.write_text(_EXPORT_SCRIPT_CONTENT, encoding="utf-8")


def ghidra_headless_summary(sample_path: str, timeout_sec: int = 180) -> Dict[str, Any]:
    """
    Runs Ghidra analyzeHeadless in a temporary project and executes a lightweight script (if provided).
    Returns a dict with rc/stdout/stderr/runtime_ms and 'skipped' info when not runnable.

    Requires env var:
      MALHAUS_GHIDRA_DIR=/path/to/ghidra_root   (the dir containing support/analyzeHeadless)

    Optional env vars:
      MALHAUS_GHIDRA_SCRIPT=SomeScript.py      (if set, will run in addition to ExportTriage.py)
    """
    t0 = time.time()

    ghidra_dir = os.environ.get("MALHAUS_GHIDRA_DIR", "").strip()
    if not ghidra_dir:
        return {
            "skipped": True,
            "reason": "MALHAUS_GHIDRA_DIR not set",
            "rc": None,
            "stdout": "",
            "stderr": "",
            "runtime_ms": int((time.time() - t0) * 1000),
        }

    ghidra_dir = str(Path(ghidra_dir).resolve())
    headless = Path(ghidra_dir) / "support" / "analyzeHeadless"
    if not headless.exists():
        return {
            "skipped": True,
            "reason": f"analyzeHeadless not found at {headless}",
            "rc": None,
            "stdout": "",
            "stderr": "",
            "runtime_ms": int((time.time() - t0) * 1000),
        }

    ok, msg = _java_ok()
    if not ok:
        return {
            "skipped": True,
            "reason": msg,
            "rc": None,
            "stdout": "",
            "stderr": msg,
            "runtime_ms": int((time.time() - t0) * 1000),
        }

    sample = Path(sample_path).resolve()
    if not sample.exists():
        return {
            "skipped": True,
            "reason": f"sample not found: {sample}",
            "rc": None,
            "stdout": "",
            "stderr": "",
            "runtime_ms": int((time.time() - t0) * 1000),
        }

    # Optional: your ghidra scripts dir (drop scripts there)
    scripts_dir = Path(__file__).resolve().parent / "ghidra_scripts"
    _ensure_export_script(scripts_dir)

    # Optional user script (kept for compatibility with your existing env var)
    user_script_name = os.environ.get("MALHAUS_GHIDRA_SCRIPT", "").strip()

    with tempfile.TemporaryDirectory(prefix="malhaus_ghidra_") as td:
        proj_dir = Path(td) / "proj"
        proj_dir.mkdir(parents=True, exist_ok=True)

        proj_name = "malhaus_tmp"
        out_json = Path(td) / "triage.json"

        cmd = [
            str(headless),
            str(proj_dir),
            proj_name,
            "-import",
            str(sample),
            "-analysisTimeoutPerFile",
            "120",
        ]

        # Script path: always add our scripts dir
        cmd += ["-scriptPath", str(scripts_dir)]

        # Always run our exporter to produce a compact JSON artifact
        cmd += ["-postScript", _EXPORT_SCRIPT_NAME, str(out_json)]

        # If user requested an additional script, run it after exporter (still captured, but filtered)
        if user_script_name:
            cmd += ["-postScript", user_script_name]

        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            runtime_ms = int((time.time() - t0) * 1000)

            # Read triage artifact (high-signal) and append it into stdout in a safe way
            triage_text = ""
            if out_json.exists():
                triage_text = out_json.read_text(encoding="utf-8", errors="replace").strip()

                # Sanity: ensure it's valid JSON; if not, keep raw
                try:
                    json.loads(triage_text)
                except Exception:
                    pass

            filtered_stdout = _filter_ghidra_output(p.stdout or "", keep_tail=200)
            filtered_stderr = _filter_ghidra_output(p.stderr or "", keep_tail=200)

            # IMPORTANT: keep return format identical (stdout/stderr/rc/etc.)
            # We place the triage JSON into stdout, because your pipeline likely reads stdout.
            # If stdout already has useful content, we append it after the JSON with a separator.
            if triage_text:
                combined_stdout = triage_text
                if filtered_stdout.strip():
                    combined_stdout += "\n\n---\n# ghidra_log_tail\n" + filtered_stdout
            else:
                combined_stdout = filtered_stdout

            return {
                "skipped": False,
                "reason": "",
                "rc": int(p.returncode),
                "stdout": combined_stdout,
                "stderr": filtered_stderr,
                "runtime_ms": runtime_ms,
                "cmd": " ".join(cmd)[:2000],
            }

        except subprocess.TimeoutExpired:
            runtime_ms = int((time.time() - t0) * 1000)
            return {
                "skipped": True,
                "reason": f"timeout after {timeout_sec}s",
                "rc": None,
                "stdout": "",
                "stderr": f"timeout after {timeout_sec}s",
                "runtime_ms": runtime_ms,
                "cmd": " ".join(cmd)[:2000],
            }
        except Exception as e:
            runtime_ms = int((time.time() - t0) * 1000)
            return {
                "skipped": True,
                "reason": f"exception: {e}",
                "rc": None,
                "stdout": "",
                "stderr": str(e),
                "runtime_ms": runtime_ms,
            }
