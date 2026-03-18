import subprocess, os, json, re, base64, hashlib
from pathlib import Path
from shutil import which
from typing import Dict, Any, List, Optional

import pefile

TIMEOUT = 120
MAX = 450000

BASE_DIR = Path(__file__).resolve().parents[1]
TOOLS_DIR = BASE_DIR / "tools"
EXTRACT_DIR = BASE_DIR / "extracted"
EXTRACT_DIR.mkdir(exist_ok=True)

def run(cmd: List[str], timeout: int = TIMEOUT, max_bytes: int = MAX) -> Dict[str, Any]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
        return {
            "cmd": " ".join(cmd),
            "stdout": p.stdout[:max_bytes].decode(errors="replace"),
            "stderr": p.stderr[:max_bytes].decode(errors="replace"),
            "rc": p.returncode,
            "ok": True,
        }
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "stdout": "", "stderr": "TIMEOUT", "rc": None, "ok": False}
    except Exception as e:
        return {"cmd": " ".join(cmd), "stdout": "", "stderr": f"EXCEPTION: {type(e).__name__}: {e}", "rc": None, "ok": False}


def run_jailed(cmd: List[str], sample_path: str, timeout: int = TIMEOUT, max_bytes: int = MAX) -> Dict[str, Any]:
    """
    Run cmd inside a firejail sandbox if available.
    - No network access (--net=none)
    - Cannot gain root (--noroot)
    - Isolated /tmp (--private-tmp)
    - Read-only filesystem except the sample file and extracted/ dir
    Falls back to plain run() if firejail is not installed.
    """
    if not which("firejail"):
        return run(cmd, timeout=timeout, max_bytes=max_bytes)

    sample = Path(sample_path).resolve()
    # firejail --whitelist restricts $HOME visibility: only whitelisted paths are
    # accessible. We must include the venv (oletools, floss, etc. live there) and
    # the tools/ dir, otherwise commands installed under $HOME show "command not found".
    jail_cmd = [
        "firejail",
        "--quiet",
        "--noprofile",
        "--net=none",
        "--noroot",
        "--private-tmp",
        f"--read-only={sample}",
        f"--whitelist={sample}",
        f"--whitelist={EXTRACT_DIR}",
        f"--whitelist={BASE_DIR / '.venv'}",
        f"--whitelist={TOOLS_DIR}",
        "--",
    ] + cmd
    return run(jail_cmd, timeout=timeout, max_bytes=max_bytes)

def tool(func):
    func.is_tool = True
    return func

# make authenticode_verify behave like other tools
try:
    authenticode_verify.is_tool = True
except Exception:
    pass

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def guess_kind_from_fileinfo(fileinfo_stdout: str, path: str) -> str:
    s = (fileinfo_stdout or "").lower()
    ext = Path(path).suffix.lower()
    if "pe32" in s or "ms-dos executable" in s:
        return "pe"
    # Read magic bytes once — used for both PE and ELF disambiguation
    try:
        with open(path, "rb") as _f:
            magic = _f.read(4)
    except OSError:
        magic = b""
    # UPX-compressed: check actual magic to distinguish PE from ELF
    if "upx compressed" in s:
        if magic[:2] == b"MZ":
            return "pe"
        if magic[:4] == b"\x7fELF":
            return "elf"
        return "pe"  # safe fallback
    # MZ magic → PE regardless of file(1) output
    if magic[:2] == b"MZ":
        return "pe"
    if "elf" in s or magic[:4] == b"\x7fELF":
        return "elf"
    if "microsoft word" in s or "microsoft excel" in s or "microsoft powerpoint" in s or "ole 2" in s or "compound document" in s:
        return "office"
    if "zip" in s and ext in [".docx", ".xlsx", ".pptx"]:
        return "office_openxml"
    if "ooxml" in s:
        return "office"
    if ext == ".msi" or "installation database" in s or "windows installer" in s:
        return "msi"
    if ext == ".pdf" or "pdf document" in s:
        return "pdf"
    if ext == ".lnk" or "ms windows shortcut" in s:
        return "lnk"
    if ext in (".vbs", ".vbe") or "visual basic" in s:
        return "vbs"
    if ext == ".hta":
        return "hta"
    if ext in (".zip",) or "zip archive" in s:
        return "archive"
    if ext in (".7z",) or "7-zip archive" in s:
        return "archive"
    if ext in (".rar",) or "rar archive" in s:
        return "archive"
    if ext == ".ps1" or "powershell" in s:
        return "ps1"
    if ext in [".sh", ".bash"] or "shell script" in s:
        return "shell"
    if ext in [".js", ".mjs", ".cjs"] or "javascript" in s:
        return "js"
    return "unknown"


def authenticode_verify(path: str) -> Dict:
    """
    Offline Authenticode verification (PE). Ground truth:
    - OK/Verified
    - Unsigned / no signature
    - Invalid signature / verification failure
    """
    cmd = ["osslsigncode", "verify", "-in", path]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return {"ok": p.returncode == 0, "rc": p.returncode, "stdout": out, "stderr": ""}
    except FileNotFoundError:
        return {"ok": False, "rc": 127, "stdout": "", "stderr": "osslsigncode not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": 124, "stdout": "", "stderr": "osslsigncode verify timed out"}

# ---------------- TYPE + UNIVERSAL ----------------

@tool
def file_info(path: str) -> Dict[str, Any]:
    return run_jailed(["file", "-b", path], path, timeout=15, max_bytes=40000)

@tool
def sha256(path: str) -> Dict[str, Any]:
    return run(["sha256sum", path], timeout=20, max_bytes=50000)

@tool
def strings_ascii(path: str) -> Dict[str, Any]:
    return run_jailed(["strings", "-a", "-n", "6", path], path, timeout=40, max_bytes=650000)

@tool
def ssdeep_hash(path: str) -> Dict[str, Any]:
    if which("ssdeep"):
        return run(["ssdeep", "-b", path], timeout=25, max_bytes=120000)
    return {"ok": False, "error": "ssdeep not installed"}

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p_i = c / n
            ent -= p_i * math.log2(p_i)
    return round(ent, 4)

@tool
def entropy_shannon(path: str) -> Dict[str, Any]:
    data = Path(path).read_bytes()
    return {"ok": True, "entropy": _shannon_entropy(data), "size": len(data)}

@tool
def pe_section_entropy(path: str) -> Dict[str, Any]:
    """Compute Shannon entropy per PE section. Entropy > 7.0 on executable sections suggests packing or encryption."""
    try:
        pe = pefile.PE(path, fast_load=False)
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode(errors="replace").rstrip("\x00").strip()
            data = sec.get_data()
            ent = _shannon_entropy(data)
            executable = bool(sec.Characteristics & 0x20000000)
            writable   = bool(sec.Characteristics & 0x80000000)
            sections.append({
                "name": name,
                "entropy": ent,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "executable": executable,
                "writable": writable,
                "suspicious": ent > 7.0 and executable,
            })
        return {"ok": True, "sections": sections}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------- PE (more low-level visibility) ----------------

def upx_detect(path: str) -> bool:
    """Return True if the PE appears to be UPX-packed (uses `upx -t`)."""
    if not which("upx"):
        # Fallback: check for UPX section names in raw bytes
        try:
            data = Path(path).read_bytes()
            return b"UPX0" in data or b"UPX1" in data
        except Exception:
            return False
    result = run_jailed(["upx", "-t", path], path, timeout=30, max_bytes=4096)
    return result.get("rc") == 0

@tool
def upx_unpack(path: str) -> Dict[str, Any]:
    """Decompress a UPX-packed PE in-place using `upx -d`. Returns ok=True on success."""
    if not which("upx"):
        return {"ok": False, "error": "upx not installed"}
    # upx -d modifies the file in-place so we can't use --read-only on the sample;
    # still jail it for network isolation and noroot
    result = run_jailed(["upx", "-d", path], path, timeout=60, max_bytes=65000)
    result["unpacked_path"] = path
    return result

@tool
def ghidra_malhaus(path: str) -> Dict[str,Any]:
    ghidra_m = TOOLS_DIR / "ghidra_malhaus"
    if ghidra_m.exists():
        print("Running ghidra_malhaus over: " + path)
        return run([str(ghidra_m) , path], timeout=600, max_bytes=650000)
    return {"ok": False,"error": f"ghidra_malhaus was not found {ghidra_m}"}
    

@tool
def readpe_all(path: str) -> Dict[str, Any]:
    if which("readpe"):
        return run(["readpe", "--all", path], timeout=45)
    return {"ok": False, "error": "readpe not installed"}

@tool
def pesec(path: str) -> Dict[str, Any]:
    if which("pesec"):
        return run(["pesec", path], timeout=30, max_bytes=220000)
    return {"ok": False, "error": "pesec not installed"}

@tool
def objdump_pe_headers(path: str) -> Dict[str, Any]:
    # -x includes headers/sections/imports in many cases; bounded by MAX anyway
    return run_jailed(["objdump", "-x", path], path, timeout=60)

@tool
def objdump_pe_imports_dynamic(path: str) -> Dict[str, Any]:
    # Often useful to spot suspicious imports and delay-load; also small-ish
    # (On some PEs, -p may fail; that's okay.)
    return run_jailed(["objdump", "-p", path], path, timeout=60)

@tool
def radare2_quick_json(path: str) -> Dict[str, Any]:
    if which("r2"):
        # iIj = binary info JSON, iij = imports JSON.
        # No -A flag: full analysis (aaa) is very slow on complex PE/ELF and not
        # needed just to list imports/info. -2 suppresses stderr noise.
        cmds = "e scr.color=false;iIj;iij"
        return run_jailed(["r2", "-2", "-q", "-c", cmds, path], path, timeout=60, max_bytes=650000)
    return {"ok": False, "error": "radare2 not installed"}

@tool
def radare2_entry_disasm(path: str) -> Dict[str, Any]:
    if which("r2"):
        # Cap radare2's own analysis time then disassemble entry0.
        # 'af' (analyze function) is lighter than 'aa' (analyze all).
        cmds = "e scr.color=false;e anal.timeout=15;af @ entry0;pdf @ entry0"
        return run_jailed(["r2", "-2", "-q", "-c", cmds, path], path, timeout=45, max_bytes=450000)
    return {"ok": False, "error": "radare2 not installed"}

@tool
def pe_overlay_info(path: str) -> Dict[str, Any]:
    try:
        pe = pefile.PE(path, fast_load=False)
        off = pe.get_overlay_data_start_offset()
        if off is None:
            return {"ok": True, "has_overlay": False}
        size = max(0, Path(path).stat().st_size - off)
        return {"ok": True, "has_overlay": size > 0, "overlay_offset": off, "overlay_size": size}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

@tool
def pe_imphash(path: str) -> Dict[str, Any]:
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        return {"ok": True, "imphash": pe.get_imphash()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------- ELF (more low-level visibility) ----------------

@tool
def readelf_all(path: str) -> Dict[str, Any]:
    return run_jailed(["readelf", "-a", path], path, timeout=60)

@tool
def objdump_elf_dynamic(path: str) -> Dict[str, Any]:
    # -p (program headers + dynamic section); good for DT_NEEDED/SONAME/RPATH/RUNPATH
    return run_jailed(["objdump", "-p", path], path, timeout=60, max_bytes=450000)

@tool
def ldd_deps(path: str) -> Dict[str, Any]:
    # Use readelf -d instead of ldd: extracts DT_NEEDED entries without executing
    # the binary (ldd runs the dynamic linker and can trigger malicious constructors)
    return run_jailed(["readelf", "-d", path], path, timeout=30, max_bytes=150000)

@tool
def objdump_elf_disasm(path: str) -> Dict[str, Any]:
    return run_jailed(["objdump", "-d", "-M", "intel", path], path, timeout=90)

# ---------------- OFFICE ----------------

@tool
def olevba_json(path: str) -> Dict[str, Any]:
    if which("olevba"):
        return run_jailed(["olevba", "--json", "--reveal", "--decode", path], path, timeout=150, max_bytes=650000)
    return {"ok": False, "error": "olevba not installed"}

@tool
def oledump_list(path: str) -> Dict[str, Any]:
    oledump = TOOLS_DIR / "oledump.py"
    if oledump.exists():
        return run_jailed(["python3", str(oledump), "-i", path], path, timeout=120, max_bytes=650000)
    return {"ok": False, "error": f"oledump.py not found at {oledump}"}

@tool
def oleobj_extract(path: str) -> Dict[str, Any]:
    if which("oleobj"):
        outdir = EXTRACT_DIR / "oleobj"
        _safe_mkdir(outdir)
        return run_jailed(["oleobj", "-d", str(outdir), path], path, timeout=180, max_bytes=650000)
    return {"ok": False, "error": "oleobj not installed (oletools)"}


@tool
def oledump_details(path: str) -> Dict[str,Any]:
    ole2 = TOOLS_DIR / "olemagic.sh"
    if ole2.exists():
        return run_jailed([str(ole2), path], path, timeout=60, max_bytes=650000)
    return {"ok": False,"error": f"olemagic.sh not found at {ole2}"}

@tool
def rtfobj_extract(path: str) -> Dict[str, Any]:
    if which("rtfobj"):
        outdir = EXTRACT_DIR / "rtfobj"
        _safe_mkdir(outdir)
        return run_jailed(["rtfobj", "-d", str(outdir), path], path, timeout=180, max_bytes=650000)
    return {"ok": False, "error": "rtfobj not installed (oletools)"}

@tool
def openxml_list(path: str) -> Dict[str, Any]:
    if which("zipinfo"):
        return run_jailed(["zipinfo", "-1", path], path, timeout=30, max_bytes=300000)
    return {"ok": False, "error": "zipinfo not installed"}

@tool
def openxml_extract(path: str) -> Dict[str, Any]:
    if which("unzip"):
        outdir = EXTRACT_DIR / "openxml"
        _safe_mkdir(outdir)
        return run(["unzip", "-j", "-o", path, "-d", str(outdir)], timeout=180, max_bytes=200000)
    return {"ok": False, "error": "unzip not installed"}


# ---------------- SCRIPT HELPERS ----------------

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])")

def _extract_base64_blobs(text: str, outdir: Path, limit: int = 5):
    found = []
    for i, m in enumerate(_B64_RE.finditer(text)):
        if i >= limit:
            break
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "===")
            if len(raw) < 128:
                continue
            h = _sha256_bytes(raw)
            out = outdir / f"b64_{i}_{h[:12]}.bin"
            out.write_bytes(raw)
            found.append({"file": str(out), "sha256": h, "size": len(raw), "type": "base64_blob"})
        except Exception:
            continue
    return found

@tool
def script_content(path: str) -> Dict[str, Any]:
    return run(["cat", path], timeout=20, max_bytes=650000)

@tool
def shell_lint(path: str) -> Dict[str, Any]:
    return run(["bash", "-n", path], timeout=10, max_bytes=100000)

@tool
def js_beautify(path: str) -> Dict[str, Any]:
    if which("js-beautify"):
        return run(["js-beautify", path], timeout=40, max_bytes=650000)
    return {"ok": False, "error": "js-beautify not installed"}

# ---------------- EMBEDDED PAYLOAD EXTRACTION ----------------

@tool
def extract_payloads(path: str) -> Dict[str, Any]:
    p = Path(path)
    info = file_info(path)
    kind = guess_kind_from_fileinfo(info.get("stdout", ""), path)

    outdir = EXTRACT_DIR / f"{p.name}_{int(p.stat().st_mtime)}"
    _safe_mkdir(outdir)

    extracted = []
    notes = []

    if kind == "pe":
        try:
            pe = pefile.PE(path, fast_load=False)
            off = pe.get_overlay_data_start_offset()
            if off is not None:
                overlay = p.read_bytes()[off:]
                if overlay:
                    h = _sha256_bytes(overlay)
                    out = outdir / f"pe_overlay_{h[:12]}.bin"
                    out.write_bytes(overlay)
                    extracted.append({"file": str(out), "sha256": h, "size": len(overlay), "type": "pe_overlay"})
        except Exception as e:
            notes.append(f"PE overlay extraction failed: {type(e).__name__}: {e}")

    if kind in ["office"]:
        if which("oleobj"):
            run(["oleobj", "-d", str(outdir), path], timeout=180, max_bytes=200000)
        if which("rtfobj"):
            run(["rtfobj", "-d", str(outdir), path], timeout=180, max_bytes=200000)

    if kind == "office_openxml":
        if which("unzip"):
            run(["unzip", "-j", "-o", "-q", path, "-d", str(outdir)], timeout=180, max_bytes=200000)
            vba = list(outdir.rglob("vbaProject.bin"))
            if vba:
                notes.append(f"Found vbaProject.bin: {vba[0]}")

    if kind in ["ps1", "shell", "js"]:
        try:
            text = p.read_text(errors="replace")
            extracted.extend(_extract_base64_blobs(text, outdir, limit=8))
        except Exception as e:
            notes.append(f"Script base64 extraction failed: {type(e).__name__}: {e}")

    # enumerate extracted files
    for f in outdir.rglob("*"):
        if f.is_file():
            try:
                sz = f.stat().st_size
                if sz == 0:
                    continue
                h = _sha256_file(f)
                extracted.append({"file": str(f), "sha256": h, "size": sz, "type": "extracted_file"})
            except Exception:
                continue

    # dedupe by path (prefer specific types over generic extracted_file)
    uniq = {}
    for e in extracted:
        f = e.get("file")
        if not f:
            continue
        if f not in uniq:
            uniq[f] = e
            continue
        prev = uniq[f]
        prev_t = str(prev.get("type", "") or "").lower()
        new_t  = str(e.get("type", "") or "").lower()
        # never overwrite a specific typed artifact with the generic "extracted_file"
        if prev_t != "extracted_file" and new_t == "extracted_file":
            continue
        # but do overwrite generic with specific
        if prev_t == "extracted_file" and new_t != "extracted_file":
            uniq[f] = e
            continue
        # otherwise keep the first
        # (stable results; avoids flip-flopping)
        continue
    extracted = list(uniq.values())

    return {
        "ok": True,
        "kind": kind,
        "output_dir": str(outdir),
        "extracted": extracted[:200],
        "notes": notes[:30],
    }

# ---------------- FLOSS ----------------

@tool
def floss_strings(path: str) -> Dict[str, Any]:
    """Run FLARE FLOSS to extract deobfuscated stack strings and encoded strings missed by 'strings'. Falls back to strings (ASCII + UTF-16LE) for non-PE formats."""
    if not which("floss"):
        return {"ok": False, "error": "floss not installed (pip install flare-floss)"}
    result = run_jailed(["floss", path], path, timeout=120, max_bytes=650000)
    stderr = result.get("stderr", "") or ""
    if result.get("rc", 0) != 0 and "FLOSS currently supports" in stderr:
        ascii_r = run_jailed(["strings", "-a", "-n", "5", path], path, timeout=60, max_bytes=300000)
        utf16_r = run_jailed(["strings", "-a", "-n", "5", "-e", "l", path], path, timeout=60, max_bytes=300000)
        combined = ""
        if ascii_r.get("stdout"):
            combined += "=== ASCII strings ===\n" + ascii_r["stdout"]
        if utf16_r.get("stdout"):
            combined += "\n=== UTF-16LE strings ===\n" + utf16_r["stdout"]
        return {
            "ok": True,
            "fallback": "strings",
            "stdout": combined[:650000],
            "stderr": f"FLOSS not supported for this format. Fell back to strings.\nFLOSS error: {stderr[:200]}",
            "rc": 0,
        }
    return result


# ---------------- PDF ----------------

@tool
def pdf_analysis(path: str) -> Dict[str, Any]:
    """Analyze PDF for suspicious keywords (/JS, /OpenAction, /Launch, /EmbeddedFile, etc.) and extract strings."""
    result: Dict[str, Any] = {"ok": True}

    # Binary keyword scan — works without any extra lib
    _suspicious = [b"/JS", b"/JavaScript", b"/AA", b"/OpenAction", b"/Launch",
                   b"/EmbeddedFile", b"/AcroForm", b"/XFA", b"/RichMedia",
                   b"/URI", b"/SubmitForm", b"/ImportData", b"/GoToR"]
    try:
        data = Path(path).read_bytes()
        result["keyword_hits"] = {
            kw.decode(): data.count(kw) for kw in _suspicious if data.count(kw) > 0
        }
        result["stream_count"] = data.count(b"stream")
        result["object_count"] = data.count(b" obj")
    except Exception as e:
        result["keyword_scan_error"] = str(e)

    # pdfid.py (Didier Stevens)
    pdfid = TOOLS_DIR / "pdfid.py"
    if pdfid.exists():
        result["pdfid"] = run_jailed(["python3", str(pdfid), path], path, timeout=60, max_bytes=200000)

    # pdf-parser.py stats
    pdfparser = TOOLS_DIR / "pdf-parser.py"
    if pdfparser.exists():
        result["pdf_parser_stats"] = run_jailed(
            ["python3", str(pdfparser), "--stats", path], path, timeout=60, max_bytes=200000
        )

    result["strings_preview"] = run_jailed(
        ["strings", "-a", "-n", "6", path], path, timeout=40, max_bytes=200000
    ).get("stdout", "")[:8000]

    # Build a unified stdout for downstream consumers (report, evidence pack, LLM)
    lines = []
    if result.get("keyword_hits"):
        lines.append("=== Suspicious keyword hits ===")
        for kw, count in result["keyword_hits"].items():
            lines.append(f"  {kw}: {count}")
    lines.append(f"stream_count: {result.get('stream_count', 0)}")
    lines.append(f"object_count: {result.get('object_count', 0)}")
    if result.get("pdfid", {}).get("stdout"):
        lines.append("\n=== pdfid ===")
        lines.append(result["pdfid"]["stdout"][:3000])
    if result.get("pdf_parser_stats", {}).get("stdout"):
        lines.append("\n=== pdf-parser stats ===")
        lines.append(result["pdf_parser_stats"]["stdout"][:3000])
    if result.get("strings_preview"):
        lines.append("\n=== strings preview ===")
        lines.append(result["strings_preview"][:2000])
    result["stdout"] = "\n".join(lines)

    return result


# ---------------- LNK ----------------

@tool
def lnk_analysis(path: str) -> Dict[str, Any]:
    """Parse Windows LNK shortcut: extract target path, arguments, working dir, metadata."""
    import json as _json
    try:
        import LnkParse3
        with open(path, "rb") as fh:
            lnk = LnkParse3.lnk_file(fh)
        info = lnk.get_json()
        stdout = _json.dumps(info, indent=2, ensure_ascii=False)[:8000]
        return {"ok": True, "lnk": info, "stdout": stdout}
    except ImportError:
        pass
    except Exception as e:
        return {"ok": False, "error": f"LnkParse3 error: {e}", "stdout": f"LnkParse3 error: {e}"}
    # Fallback: strings
    s = run_jailed(["strings", "-a", "-n", "4", path], path, timeout=30, max_bytes=50000)
    fb = s.get("stdout", "")[:3000]
    return {"ok": False, "error": "LnkParse3 not installed", "strings_fallback": fb, "stdout": fb}


@tool
def exiftool_lnk(path: str) -> Dict[str, Any]:
    """
    Run exiftool on a Windows LNK shortcut to extract structured metadata:
    target file, command-line arguments, working directory, icon location,
    hotkey, creation/modification timestamps, and volume info.
    Useful when lnk_analysis output is sparse or unavailable.
    """
    if not which("exiftool"):
        return {"ok": False, "error": "exiftool not installed (apt install libimage-exiftool-perl)", "stdout": ""}
    result = run_jailed(["exiftool", "-j", path], path, timeout=30, max_bytes=30000)
    # -j gives JSON; if it fails fall back to plain text
    if result.get("rc") != 0 or not (result.get("stdout") or "").strip():
        result = run_jailed(["exiftool", path], path, timeout=30, max_bytes=30000)
    return result


@tool
def lecmd_lnk(path: str) -> Dict[str, Any]:
    """
    Run LECmd (Eric Zimmerman's forensic LNK parser) on a Windows LNK shortcut.
    Provides the most complete LNK analysis: shell item IDs, volume serial numbers,
    machine identifier, tracker data, network share info, and full argument decoding.
    Requires LECmd.exe (set MALHAUS_LECMD_PATH) and mono on Linux.
    """
    lecmd = os.environ.get("MALHAUS_LECMD_PATH", "")
    if not lecmd:
        for candidate in ["/opt/lecmd/LECmd.exe", "/opt/LECmd/LECmd.exe",
                          "/tools/LECmd.exe", "/usr/local/share/lecmd/LECmd.exe"]:
            if os.path.exists(candidate):
                lecmd = candidate
                break
    if not lecmd:
        return {
            "ok": False,
            "error": "LECmd not found. Download from https://github.com/EricZimmerman/LECmd and set MALHAUS_LECMD_PATH=/path/to/LECmd.exe",
            "stdout": "",
        }
    # On Linux run under mono; on Windows call directly
    mono = which("mono")
    cmd = ([mono, lecmd] if mono else [lecmd]) + ["-f", path, "--csv", "-"]
    result = run_jailed(cmd, path, timeout=60, max_bytes=50000)
    # LECmd writes summary to stdout and errors to stderr
    if not (result.get("stdout") or "").strip() and (result.get("stderr") or "").strip():
        result["stdout"] = result["stderr"]
    return result


# ---------------- ARCHIVE (ZIP / 7z / RAR) ----------------

def _check_archive_uncompressed_size(path: str, max_bytes: int, password: str = "") -> Optional[str]:
    """
    Read archive metadata WITHOUT extracting and return an error string if the
    total uncompressed size exceeds max_bytes, or None if it is acceptable.

    For ZIP files Python's zipfile reads only the central directory (a few KB at
    the end of the file) — no decompression happens at all.
    For 7z/RAR/other formats we run `7z l -slt` which lists sizes without writing
    anything to disk.

    This stops decompression-bomb attacks (e.g. a 10 KB zip that expands to 10 GB)
    before a single byte of output is written.
    """
    import zipfile as _zf
    try:
        if _zf.is_zipfile(path):
            with _zf.ZipFile(path) as zf:
                entries = zf.infolist()
            # Encrypted entries without a password are already blocked above;
            # sizes in encrypted central directories could be spoofed, so skip
            # the bomb check if all entries are encrypted and no password given.
            if entries and all(bool(e.flag_bits & 0x1) for e in entries) and not password:
                return None
            total = sum(e.file_size for e in entries)
            if total > max_bytes:
                return (
                    f"archive bomb rejected: total uncompressed size "
                    f"{total / (1024 * 1024):.1f} MB exceeds "
                    f"{max_bytes / (1024 * 1024):.0f} MB limit"
                )
            return None
    except Exception:
        pass  # not a ZIP or unreadable — fall through to 7z listing

    # For RAR, 7z, and other formats: use `7z l -slt` to read metadata only
    try:
        list_result = run(["7z", "l", "-slt", path], timeout=15, max_bytes=500000)
        stdout = list_result.get("stdout") or ""
        total = 0
        for line in stdout.splitlines():
            if line.startswith("Size = "):
                try:
                    total += int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
        if total > max_bytes:
            return (
                f"archive bomb rejected: total uncompressed size "
                f"{total / (1024 * 1024):.1f} MB exceeds "
                f"{max_bytes / (1024 * 1024):.0f} MB limit"
            )
    except Exception:
        pass  # listing failed — let the extraction attempt and rely on disk quota

    return None


def _archive_extract_impl(path: str, password: str = "", _depth: int = 0, _max_depth: int = 4) -> Dict[str, Any]:
    if not which("7z"):
        return {"ok": False, "error": "7z (p7zip-full) not installed"}

    import config as _cfg
    import zipfile as _zf

    # --- Pre-extraction encryption check (ZIP only) ---
    # For encrypted ZIPs without a password, 7z may:
    #   a) fail cleanly with rc=2 (AES-256) — caught later, or
    #   b) "succeed" producing garbage files (ZipCrypto empty password) — rc=0,
    #      wrong_password never set, and the rest of the pipeline analyses noise.
    # Detect this early via the ZIP central directory before touching the filesystem.
    if not password:
        try:
            if _zf.is_zipfile(path):
                with _zf.ZipFile(path) as _zobj:
                    _entries = _zobj.infolist()
                if _entries and any(bool(e.flag_bits & 0x1) for e in _entries):
                    return {
                        "ok": False,
                        "wrong_password": True,
                        "extract_rc": None,
                        "error": "Archive is encrypted — please resubmit and provide the password.",
                    }
        except Exception:
            pass  # not a ZIP or unreadable — continue to extraction

    max_bytes = getattr(_cfg, "MAX_UPLOAD_BYTES", 10 * 1024 * 1024)
    bomb_error = _check_archive_uncompressed_size(path, max_bytes, password=password)
    if bomb_error:
        return {"ok": False, "error": bomb_error}

    p = Path(path)
    outdir = EXTRACT_DIR / f"arc_{p.stem}_{int(p.stat().st_mtime)}"
    _safe_mkdir(outdir)

    cmd = ["7z", "x", f"-o{outdir}", "-y", "-bd"]
    if password:
        cmd.append(f"-p{password}")
    cmd.append(path)
    extract_result = run_jailed(cmd, path, timeout=120, max_bytes=200000)

    # Detect wrong/missing password: 7z returns rc=2 and leaves outdir empty
    extract_rc = extract_result.get("rc", 0)
    combined_out = (extract_result.get("stdout") or "") + (extract_result.get("stderr") or "")
    wrong_password = extract_rc != 0 and (
        "wrong password" in combined_out.lower()
        or "encrypted" in combined_out.lower()
        or not any(outdir.rglob("*"))
    )
    if wrong_password:
        return {
            "ok": False,
            "wrong_password": True,
            "extract_rc": extract_rc,
            "error": "Archive extraction failed — wrong or missing password.",
        }

    # Priority order for promotion: pe > elf > msi > office_openxml > office > script > pdf > lnk
    _PRIO = {"pe": 0, "elf": 1, "msi": 2, "office_openxml": 3, "office": 4,
             "ps1": 5, "vbs": 5, "hta": 5, "js": 5, "shell": 5,
             "pdf": 6, "lnk": 7}

    _EXT_KIND = {
        ".ps1": "ps1", ".vbs": "vbs", ".vbe": "vbs", ".hta": "hta",
        ".js": "js", ".bat": "shell", ".cmd": "shell", ".sh": "shell",
        ".msi": "msi", ".pdf": "pdf", ".lnk": "lnk",
        ".doc": "office", ".xls": "office", ".ppt": "office", ".rtf": "office",
        ".docm": "office", ".xlsm": "office", ".pptm": "office",
        ".docx": "office_openxml", ".xlsx": "office_openxml", ".pptx": "office_openxml",
    }

    # Magic bytes for extension-less files (e.g. VirusTotal samples)
    _MAGIC_KIND = [
        (b"MZ",                                   2, "pe"),
        (b"\x7fELF",                              4, "elf"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",   8, "office"),   # OLE2: Office/MSI
        (b"%PDF",                                  4, "pdf"),
        (b"\x4C\x00\x00\x00",                     4, "lnk"),      # Windows Shell Link
        (b"{\x5crtf",                              5, "office"),   # RTF
    ]

    all_files: list = []
    candidates: list = []   # (priority, size, path, kind)
    script_files: list = []

    for f in outdir.rglob("*"):
        if not f.is_file():
            continue
        try:
            sz = f.stat().st_size
            all_files.append({"path": str(f.relative_to(outdir)), "size": sz})
            with open(f, "rb") as fh:
                header = fh.read(8)
            ext = f.suffix.lower()

            # 1. Magic-byte detection first (works for extension-less files too)
            kind_f = None
            for magic_bytes, nbytes, mk in _MAGIC_KIND:
                if header[:nbytes] == magic_bytes:
                    # OLE2 could be MSI — prefer extension hint if available
                    if mk == "office" and ext == ".msi":
                        kind_f = "msi"
                    else:
                        kind_f = mk
                    break

            # 1b. Extension fallback BEFORE archive check — critical for OpenXML files:
            # .docx/.xlsx/.pptx are ZIP files (PK magic) but must be promoted as
            # office_openxml, not recursed into as nested archives.
            if kind_f is None and ext in _EXT_KIND:
                kind_f = _EXT_KIND[ext]

            # 2. Detect nested archives — only if we haven't identified the file yet.
            # This prevents OpenXML docs (ZIP-based) from being wrongly recursed into.
            _ARCHIVE_MAGIC = [
                (b"\x50\x4B\x03\x04", 4),           # ZIP
                (b"\x52\x61\x72\x21\x1A\x07\x00", 7), # RAR5
                (b"\x52\x61\x72\x21\x1A\x07\x01", 7), # RAR4
                (b"\x37\x7A\xBC\xAF\x27\x1C", 6),    # 7z
                (b"\x1F\x8B", 2),                     # gzip
            ]
            _ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".tgz", ".tar"}
            is_nested_archive = (
                kind_f is None
                and (
                    any(header[:nb] == mb for mb, nb in _ARCHIVE_MAGIC)
                    or ext in _ARCHIVE_EXTS
                )
            )
            if is_nested_archive:
                if _depth < _max_depth:
                    sub = _archive_extract_impl(str(f), password=password,
                                                _depth=_depth + 1, _max_depth=_max_depth)
                    if sub.get("ok") and sub.get("promoted_file") and sub.get("promoted_kind"):
                        sub_prio = _PRIO.get(sub["promoted_kind"], 99)
                        candidates.append((sub_prio, sz, Path(sub["promoted_file"]), sub["promoted_kind"]))
                # Never promote the raw archive file itself
                continue

            # 3. Skip unrecognized files
            if kind_f is None:
                continue

            prio = _PRIO.get(kind_f, 99)
            candidates.append((prio, sz, f, kind_f))

            if kind_f in ("ps1", "vbs", "hta", "js", "shell"):
                script_files.append(f)
        except Exception:
            continue

    all_files.sort(key=lambda x: x["size"], reverse=True)
    # Sort: lower priority number first, then largest by size
    candidates.sort(key=lambda x: (x[0], -x[1]))

    promoted_path = str(candidates[0][2]) if candidates else None
    promoted_kind = candidates[0][3] if candidates else None

    # Legacy field: largest_pe for backwards compat
    pe_candidates = [(sz, f) for (p, sz, f, k) in candidates if k == "pe"]
    pe_candidates.sort(reverse=True)
    largest_pe = str(pe_candidates[0][1]) if pe_candidates else None

    pe_strings = ""
    target_for_strings = largest_pe or promoted_path
    if target_for_strings:
        sr = run_jailed(["strings", "-a", "-n", "6", target_for_strings],
                        target_for_strings, timeout=40, max_bytes=200000)
        pe_strings = sr.get("stdout", "")[:10000]

    scripts: Dict[str, str] = {}
    for sf in script_files[:3]:
        try:
            scripts[sf.name] = sf.read_text(errors="replace")[:3000]
        except Exception:
            pass

    return {
        "ok": True,
        "extract_rc": extract_result.get("rc"),
        "password_used": bool(password),
        "nesting_depth": _depth,
        "file_count": len(all_files),
        "files": all_files[:50],
        "pe_count": len(pe_candidates),
        "largest_pe": largest_pe,
        "promoted_file": promoted_path,
        "promoted_kind": promoted_kind,
        "pe_strings_preview": pe_strings,
        "script_files": scripts,
    }


@tool
def archive_extract(path: str) -> Dict[str, Any]:
    """Extract ZIP/7z/RAR archive and return file listing, largest PE strings, embedded scripts."""
    return _archive_extract_impl(path, password="")


@tool
def msi_extract(path: str) -> Dict[str, Any]:
    """
    Extract an MSI installer with 7z. Returns list of extracted files,
    the path to the largest PE found inside, and a strings preview of that PE.
    """
    if not which("7z"):
        return {"ok": False, "error": "7z not installed"}

    p = Path(path)
    outdir = EXTRACT_DIR / f"msi_{p.stem}_{int(p.stat().st_mtime)}"
    _safe_mkdir(outdir)

    extract_result = run_jailed(
        ["7z", "x", path, f"-o{outdir}", "-y", "-bd"],
        path, timeout=120, max_bytes=200000,
    )

    # Walk extracted files; find PE candidates
    pe_files: list = []
    all_files: list = []
    for f in outdir.rglob("*"):
        if not f.is_file():
            continue
        try:
            sz = f.stat().st_size
            all_files.append({"path": str(f), "size": sz})
            with open(f, "rb") as fh:
                magic = fh.read(2)
            if magic == b"MZ":
                pe_files.append((sz, str(f)))
        except Exception:
            continue

    pe_files.sort(reverse=True)
    all_files.sort(key=lambda x: x["size"], reverse=True)
    largest_pe = pe_files[0][1] if pe_files else None

    pe_strings = ""
    if largest_pe:
        s_res = run_jailed(
            ["strings", "-a", "-n", "6", largest_pe],
            largest_pe, timeout=40, max_bytes=300000,
        )
        pe_strings = s_res.get("stdout", "")

    return {
        "ok": True,
        "extract_rc": extract_result.get("rc"),
        "extract_stderr": extract_result.get("stderr", "")[:1000],
        "extracted_files": all_files[:50],
        "pe_count": len(pe_files),
        "largest_pe": largest_pe,
        "pe_strings_preview": pe_strings[:20000],
    }


# ---------------- BYTE HEATMAP (visualization, not an LLM tool) ----------------

def byte_heatmap(path: str) -> Dict[str, Any]:
    """
    Generate a byte heatmap of a file as a base64-encoded PNG (always 256x256).
    Samples the whole file evenly so large files still show full structure.
    Returns {"ok": True, "b64": "<base64 png>", "file_size": N}
    """
    try:
        import io, base64
        import numpy as np
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        with open(path, "rb") as f:
            data = np.frombuffer(f.read(), dtype=np.uint8)

        n = 256 * 256  # always 256×256
        if len(data) >= n:
            indices = np.linspace(0, len(data) - 1, n, dtype=int)
            sampled = data[indices]
        else:
            sampled = np.pad(data, (0, n - len(data)), "constant")

        matrix = sampled.reshape((256, 256))

        fig, ax = plt.subplots(figsize=(3, 3), dpi=85)
        fig.patch.set_facecolor("#07090c")
        ax.imshow(matrix, cmap="viridis", interpolation="nearest", aspect="equal")
        ax.axis("off")
        fig.tight_layout(pad=0)

        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight", pad_inches=0, facecolor="#07090c")
        plt.close(fig)
        buf.seek(0)
        return {"ok": True, "b64": base64.b64encode(buf.read()).decode("ascii"), "file_size": int(len(data))}
    except Exception as e:
        return {"ok": False, "error": str(e)}


ALL_TOOLS = [
    # universal
    file_info, sha256, ssdeep_hash, entropy_shannon, strings_ascii, extract_payloads, authenticode_verify,

    # PE low-level
    upx_unpack, readpe_all, pesec, objdump_pe_headers, objdump_pe_imports_dynamic,
    radare2_quick_json, radare2_entry_disasm, pe_overlay_info, pe_imphash, pe_section_entropy,
    ghidra_malhaus,

    # ELF low-level
    readelf_all, objdump_elf_dynamic, ldd_deps, objdump_elf_disasm,

    # Office
    olevba_json, oledump_list, oledump_details, oleobj_extract, rtfobj_extract, openxml_list, openxml_extract,

    # scripts
    script_content, shell_lint, js_beautify,

    # MSI installer
    msi_extract,

    # deobfuscation
    floss_strings,

    # new file types
    pdf_analysis, lnk_analysis, exiftool_lnk, lecmd_lnk, archive_extract,
]


def detect_file_type(path: str) -> str:
    """Canonical file type detector used for DB + report consistency."""
    info = file_info(path)
    return guess_kind_from_fileinfo(info.get("stdout", ""), path)
