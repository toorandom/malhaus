"""
String -> code links without Ghidra (radare2 + pefile).

Every string constant is classified by its SHAPE (registry path, file path, URL/endpoint, command
line, JSON field) and resolved to the function(s) that reference it: directly, or through an array
of string pointers. Each function is reported with the strings it uses and the APIs it reaches
(its own calls + callees up to depth 2). No family-, vendor- or product-specific keyword lists:
"loops over 12 registry keys and calls RegOpenKeyExW" is visible whatever the keys are.

Same idea and shape rules as the STRING->CODE LINKS section of tools/ghidra_malhaus (keep in sync),
but takes seconds instead of minutes, so it runs on every PE/ELF including sub-components.
"""
import json
import os
import re
import struct
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Set

# ---- string shapes (mirror of the Java SHAPE_* patterns) ----
SHAPE_REG = re.compile(r"(?i)^(?:\\?registry\\machine\\|HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\|SOFTWARE\\|SYSTEM\\|HARDWARE\\|SAM\\|SECURITY\\)|\\CurrentVersion\\|\\CurrentControlSet\\")
SHAPE_URL = re.compile(r"(?i)^(?:https?|ftp|wss?)://|^/[a-z0-9_.-]+/[a-z0-9_./?=&%{}-]*$|^/[a-z0-9_-]{2,}\?|^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|co|io|ru|cn|xyz|top|info|biz|online|site|app|dev)$")
SHAPE_CMD = re.compile(r"(?i)(?:^|\s|\")(?:cmd(?:\.exe)?\s+/[ck]\b|/c\s+\S|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|schtasks|bitsadmin|certutil|wmic|reg(?:\.exe)?\s+(?:add|delete|query)|sc(?:\.exe)?\s+(?:create|config|start|stop)|net\s+(?:user|stop|start))\b|\s/[a-z]{1,3}\s+\S+\.exe\b")
SHAPE_PATH = re.compile(r"(?i)^[a-z]:\\|^\\\\|^%[a-z_]+%\\|^\{[a-z]+\}\\|\\(?:AppData|Local|Roaming|Temp|ProgramData|Program Files|System32|Users|Startup|Prefetch|User Data|Profiles)\b|\\[A-Za-z0-9 _.$~()-]{2,}\\[A-Za-z0-9 _.$~()-]{2,}|\\[^\\\s]+\.(?:exe|dll|sys|dat|db|sqlite|json|log|ini|lnk|tmp|bat|ps1|vbs|token)$")
SHAPE_JSON = re.compile(r"\"[A-Za-z_][A-Za-z0-9_]{2,40}\"\s*:")
# POSIX roots are paths, not URL paths (/api/gate stays "url")
SHAPE_POSIX = re.compile(r"^/(?:usr|etc|bin|sbin|tmp|var|proc|dev|home|root|opt|lib|lib32|lib64|sys|run|mnt|srv|boot|Library|Users|Applications|System|private)(?:/|$)")
# forward-slash relative paths with >= 2 separators (std::filesystem style "Vendor/App/User Data"; not MIME
# types like text/html) and bare data-file names
SHAPE_PATH2 = re.compile(r"(?i)^[a-z0-9_.][\w .-]*(?:/[\w .-]+){2,}/?$|^[\w.-]+\.(?:sqlite|db|json|dat|log|token|ini|cfg|key|pem)$")
SHAPES = ("registry", "url", "cmdline", "json", "path")


def shape_of(s: str) -> Optional[str]:
    t = (s or "").strip()
    if len(t) < 4 or len(t) > 600:
        return None
    if SHAPE_REG.search(t):
        return "registry"
    if SHAPE_POSIX.search(t):
        return "path"
    if SHAPE_URL.search(t):
        return "url"
    if SHAPE_CMD.search(t):
        return "cmdline"
    if SHAPE_JSON.search(t):
        return "json"
    if SHAPE_PATH.search(t) or SHAPE_PATH2.search(t):
        return "path"
    return None


# ---- API groups (substring match; "=name" = exact) ----
API_GROUPS = {
    "registry": ["regopenkey", "regqueryvalue", "regenumkey", "regenumvalue", "regsetvalue", "regcreatekey",
                 "regdeletekey", "reggetvalue", "ntopenkey", "ntqueryvaluekey", "shgetvalue", "regloadkey"],
    "file": ["createfile", "readfile", "writefile", "copyfile", "movefile", "deletefile", "findfirstfile",
             "findnextfile", "getfileattributes", "pathfileexists", "fopen", "_wfopen", "sqlite3_open", "getfilesize",
             "createdirectory", "shgetfolderpath", "shgetknownfolderpath", "expandenvironmentstrings", "gettemppath"],
    "process": ["createprocess", "shellexecute", "winexec", "openprocess", "terminateprocess",
                "createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses", "virtualallocex",
                "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext",
                "resumethread", "=system", "=_wsystem", "_popen", "execve", "fork"],
    "network": ["winhttp", "internetopen", "internetconnect", "httpopenrequest", "httpsendrequest",
                "internetreadfile", "urldownloadtofile", "wsastartup", "=socket", "=connect", "=send", "=recv",
                "getaddrinfo", "gethostbyname", "wsasend", "wsarecv", "curl_easy"],
    "system-info": ["getcomputername", "getusername", "getversionex", "rtlgetversion", "globalmemorystatus",
                    "getsysteminfo", "getnativesysteminfo", "getadaptersinfo", "getadaptersaddresses",
                    "getdiskfreespace", "getvolumeinformation", "getsystemmetrics", "enumdisplaymonitors",
                    "gettickcount64", "getsystemfirmwaretable", "setupdigetclassdevs", "getlogicaldrives",
                    "getsystemdefaultlangid", "getkeyboardlayout", "getcursorpos", "getlastinputinfo", "=uname",
                    "sysinfo", "gethostname"],
}

_RE_IMP = re.compile(r"(?:^|\.)imp\.(?:[^.]+\.dll_)?(.+)$", re.IGNORECASE)


def _api_name(refname: str) -> Optional[str]:
    """sym.imp.KERNEL32.dll_CreateFileW -> CreateFileW; reloc.X / sym.imp.X -> X."""
    m = _RE_IMP.search(refname or "")
    if m:
        return m.group(1)
    if refname and refname.startswith("reloc."):
        return refname[6:].split("_", 1)[-1] if ".dll_" in refname else refname[6:]
    return None


def _api_match(name: str, needle: str) -> bool:
    lo = name.lower()
    return lo == needle[1:] if needle.startswith("=") else needle in lo


def api_groups(apis: Set[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for g, needles in API_GROUPS.items():
        hit = sorted(a for a in apis if any(_api_match(a, n) for n in needles))
        if hit:
            out[g] = hit
    return out


def _func_of(name: str) -> Optional[str]:
    """axj 'name' of the referencing location: fcn.140009430+418 -> fcn.140009430 (None if not in a function)."""
    if not name or name.startswith(("section.", "segment.", "str.", "reloc.", "obj.")):
        return None
    return name.rsplit("+", 1)[0]


_R2_ESC = re.compile(r"\\(\\|n|t|r|\"|e|x[0-9a-fA-F]{2})")
_R2_ESC_MAP = {"\\": "\\", "n": "\n", "t": "\t", "r": "\r", '"': '"', "e": "\x1b"}


def _r2_unescape(s: str) -> str:
    """radare2 izj escapes string contents (\\\\, \\n, \\xNN ...)."""
    return _R2_ESC.sub(lambda m: _R2_ESC_MAP.get(m.group(1)) or chr(int(m.group(1)[1:], 16)), s or "")


def _json_lines(text: str) -> List[Any]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("[") or line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


class _PEView:
    """Read pointers from a PE's initialized, non-executable sections by virtual address."""

    def __init__(self, path: str):
        import pefile
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.psz = 8 if self.pe.FILE_HEADER.Machine in (0x8664, 0xAA64) else 4
        self.secs = []
        for s in self.pe.sections:
            if s.Characteristics & 0x20000000:  # executable
                continue
            self.secs.append((self.base + s.VirtualAddress, s.get_data()))

    def ptr(self, va: int) -> Optional[int]:
        for start, data in self.secs:
            off = va - start
            if 0 <= off <= len(data) - self.psz:
                return struct.unpack_from("<Q" if self.psz == 8 else "<I", data, off)[0]
        return None


def build_links(strings: List[Dict[str, Any]], refs: List[Dict[str, Any]], pe: Optional[_PEView] = None,
                max_funcs: int = 30) -> List[Dict[str, Any]]:
    """strings: r2 izj entries (vaddr, string); refs: r2 axj entries (from, addr, type, name, refname)."""
    by_addr = {int(s["vaddr"]): _r2_unescape(s.get("string", "")) for s in strings if s.get("vaddr")}
    referenced = {int(r["addr"]) for r in refs if r.get("addr") is not None}
    links: Dict[str, Dict[str, Any]] = {}
    calls: Dict[str, Set[str]] = defaultdict(set)   # fcn -> callee fcns
    apis: Dict[str, Set[str]] = defaultdict(set)    # fcn -> imported APIs called directly
    fcn_addr: Dict[str, int] = {}
    table_cache: Dict[int, List[str]] = {}

    def table_at(va: int) -> List[str]:
        """Strings of an array of string pointers starting at va (struct arrays: small gaps allowed);
        ends at the next slot something else references (start of the next object)."""
        if va in table_cache:
            return table_cache[va]
        out: List[str] = []
        if pe is not None:
            gap = 0
            for k in range(160):
                slot = va + k * pe.psz
                if k and slot in referenced:
                    break
                v = pe.ptr(slot)
                if v is None:
                    break
                if v in by_addr:
                    out.append(by_addr[v]); gap = 0
                    continue
                if not out:
                    break  # slot 0 must already be a string pointer
                gap += 1
                if gap > 3:
                    break
        table_cache[va] = out
        return out

    for r in refs:
        fn = _func_of(r.get("name", ""))
        if not fn:
            continue
        try:
            fcn_addr.setdefault(fn, int(r.get("from", 0)) - int(r.get("name", "+0").rsplit("+", 1)[-1] or 0)
                                if "+" in r.get("name", "") else int(r.get("from", 0)))
        except ValueError:
            pass
        rtype = (r.get("type") or "").upper()
        refname = r.get("refname") or ""
        api = _api_name(refname)
        if api:
            apis[fn].add(api)
            continue
        if rtype in ("CALL", "CODE"):
            callee = _func_of(refname)
            if callee and callee != fn and rtype == "CALL":
                calls[fn].add(callee)
            continue
        to = int(r.get("addr") or 0)
        found = [by_addr[to]] if to in by_addr else table_at(to)
        for s in found:
            sh = shape_of(s)
            if not sh:
                continue
            t = s.strip().replace("\n", "\\n").replace("\r", "")
            if len(t) > 160:
                t = t[:157] + "..."
            li = links.setdefault(fn, {"function": fn, "strings": {}})
            bucket = li["strings"].setdefault(sh, [])
            if t not in bucket:
                bucket.append(t)

    memo: Dict[str, Set[str]] = {}

    def reach(fn: str, depth: int) -> Set[str]:
        if fn in memo:
            return memo[fn]
        memo[fn] = set()  # cycle guard
        out = set(apis.get(fn, ()))
        if depth > 0:
            for c in calls.get(fn, ()):
                out |= reach(c, depth - 1)
        memo[fn] = out
        return out

    result = []
    for fn, li in links.items():
        reached = set(apis.get(fn, ()))
        for c in calls.get(fn, ()):
            memo.clear()
            reached |= reach(c, 1)
        groups = api_groups(reached)
        n = {sh: len(li["strings"].get(sh, [])) for sh in SHAPES}
        sc = n["registry"] + n["url"] * 2 + n["cmdline"] * 3 + n["json"] + n["path"]
        if n["registry"] and "registry" in groups:
            sc += 4 + min(n["registry"], 12)
        if n["path"] and "file" in groups:
            sc += 3 + min(n["path"], 10)
        if n["url"] and "network" in groups:
            sc += 6
        if n["cmdline"] and "process" in groups:
            sc += 6
        if n["json"] >= 3:
            sc += 4 + min(n["json"], 20) // 2
            if "system-info" in groups:
                sc += 6
        total = sum(n.values())
        if not (total >= 2 or n["cmdline"] or (n["url"] and "network" in groups)):
            continue
        result.append({"function": fn, "address": hex(fcn_addr[fn]) if fn in fcn_addr else "",
                       "score": sc, "counts": {k: v for k, v in n.items() if v},
                       "strings": li["strings"], "apis": groups})
    result.sort(key=lambda x: (-x["score"], -sum(x["counts"].values())))
    return result[:max_funcs]


def render(links: List[Dict[str, Any]], engine: str = "radare2", per_shape: int = 14) -> str:
    lines = [f"== STRING->CODE LINKS ({engine}: functions using constant strings + the APIs they reach) =="]
    if not links:
        lines.append("No function references registry/path/URL/command/JSON-shaped strings.")
        return "\n".join(lines)
    for i, li in enumerate(links, 1):
        what = ", ".join(f"{k}={v}" for k, v in li["counts"].items())
        lines.append("")
        lines.append(f"[L{i}] link_score={li['score']}  {li['function']}"
                     + (f" @ {li['address']}" if li.get("address") else "") + f"  strings: {what}")
        if li["apis"]:
            lines.append("  reaches APIs -> " + " | ".join(f"{g}: {','.join(v)}" for g, v in li["apis"].items()))
        for sh, ss in li["strings"].items():
            for s in ss[:per_shape]:
                lines.append(f"    ({sh}) {s}")
            if len(ss) > per_shape:
                lines.append(f"    ({sh}) ... +{len(ss) - per_shape} more")
    return "\n".join(lines)


def code_links(path: str, runner: Callable[..., Dict[str, Any]], size_fast: int = 8 * 1024 * 1024) -> Dict[str, Any]:
    """radare2 analysis (aaa; aa+aar for big files or on timeout) -> izj + axj -> links. `runner` is
    run_jailed-compatible: runner(cmd, sample_path, timeout=, max_bytes=)."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return {"ok": False, "error": str(e), "stdout": ""}
    timeout = int(os.environ.get("MALHAUS_CODE_LINKS_TIMEOUT", "120"))
    plans = (["aa;aar"] if size > size_fast else ["aaa", "aa;aar"])
    notes: List[str] = []
    strings: List[Any] = []
    refs: List[Any] = []
    for analysis in plans:
        r = runner(["r2", "-2", "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true",
                    "-c", f"{analysis};izj;axj", path], path, timeout=timeout, max_bytes=80_000_000)
        out = _json_lines(r.get("stdout", ""))
        if len(out) >= 2 and isinstance(out[-2], list) and isinstance(out[-1], list):
            strings, refs = out[-2], out[-1]
            notes.append(f"radare2 analysis: {analysis} ({len(strings)} strings, {len(refs)} references)")
            break
        notes.append(f"radare2 '{analysis}' gave no usable output"
                     + (" (timeout)" if "timeout" in (r.get("stderr", "") + str(r.get("error", ""))).lower() else ""))
    if not refs:
        return {"ok": False, "error": "; ".join(notes), "stdout": ""}
    pe = None
    try:
        with open(path, "rb") as fh:
            if fh.read(2) == b"MZ":
                pe = _PEView(path)
    except Exception as e:  # noqa: BLE001 - tables are optional, direct references still work
        notes.append(f"pointer tables skipped: {type(e).__name__}")
    links = build_links(strings, refs, pe)
    text = render(links) + "\n\n" + "\n".join(notes)
    return {"ok": True, "links": links, "stdout": text}
