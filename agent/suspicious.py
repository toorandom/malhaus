import re
import math
from typing import Any, Dict, List, Set, Tuple

from agent.imports import extract_import_names_from_text

RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

RE_WIN_PATH = re.compile(r"(?i)\b[a-z]:\\(?:[^\\\s\"']+\\)*[^\\\s\"']+")

# IMPORTANT: require at least ONE slash after root and at least 2 chars in segment
# Examples allowed: /bin/busybox, /usr/lib/systemd/systemd, /root/dvr_gui/
# Examples rejected: /I, /L3, /<-t
RE_POSIX_PATH = re.compile(r"\b/(?:[A-Za-z0-9._-]{2,}/)+[A-Za-z0-9._-]{2,}/?\b")

RE_REG = re.compile(r"(?i)\bHK(?:LM|CU|CR|U|CC)\\[^\s\"']+")

RE_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
RE_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{120,}(?![0-9a-fA-F])")

RE_FLAGISH = re.compile(r"(?:(?:\s|^)[-/]{1,2}[A-Za-z]{1,})(?:\s|$)")
RE_SHELL_META = re.compile(r"[|;&><]{1,2}")

def shannon_entropy_str(s: str) -> float:
    if not s:
        return 0.0
    b = s.encode("utf-8", errors="ignore")
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    n = len(b)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def looks_base64ish(s: str) -> bool:
    if len(s) < 120:
        return False
    non = re.sub(r"[A-Za-z0-9+/=]", "", s)
    return (len(non) / len(s)) < 0.06

def looks_hexish(s: str) -> bool:
    if len(s) < 120:
        return False
    non = re.sub(r"[0-9a-fA-F]", "", s)
    return (len(non) / len(s)) < 0.04

def filter_suspicious_lines(strings_text: str, import_names: Set[str], max_lines: int = 60) -> List[Dict[str, Any]]:
    lines = []
    for raw in (strings_text or "").splitlines():
        s = raw.strip()
        if not s or len(s) < 6:
            continue
        if len(s) > 2000:
            s = s[:2000] + "…"
        lines.append(s)

    scored: List[Tuple[float, Dict[str, Any]]] = []

    for s in lines:
        tags: List[str] = []
        score = 0.0

        # IOC-shaped patterns
        if RE_URL.search(s):
            tags.append("ioc:url"); score += 6.0
        if RE_EMAIL.search(s):
            tags.append("ioc:email"); score += 5.0
        if RE_IPV4.search(s):
            tags.append("ioc:ipv4"); score += 5.0
        if RE_DOMAIN.search(s):
            tags.append("ioc:domain"); score += 2.0

        if RE_REG.search(s):
            tags.append("ioc:registry"); score += 4.0
        if RE_WIN_PATH.search(s):
            tags.append("ioc:path"); score += 2.5
        # POSIX path stricter now
        if RE_POSIX_PATH.search(s):
            tags.append("ioc:path"); score += 2.5

        # Import-guided (adaptive)
        if import_names:
            for name in import_names:
                if name in s:
                    tags.append("matches_import"); score += 4.0
                    break

        # Encoded/obfuscation-like
        ent = shannon_entropy_str(s)
        if len(s) >= 40 and ent >= 4.2:
            tags.append(f"high_entropy:{ent:.2f}"); score += 2.0

        if RE_B64.search(s) or looks_base64ish(s):
            tags.append("encoded:base64_like"); score += 4.0

        if RE_HEX.search(s) or looks_hexish(s):
            tags.append("encoded:hex_like"); score += 3.5

        # Command shape
        if RE_SHELL_META.search(s):
            tags.append("cmd:metachars"); score += 1.5
        if len(RE_FLAGISH.findall(s)) >= 2:
            tags.append("cmd:many_flags"); score += 2.0

        punct = sum(1 for c in s if c in r"\/%$^&*()[]{}<>")
        if len(s) >= 30 and (punct / len(s)) > 0.12:
            tags.append("weird:punc_dense"); score += 1.5

        if len(s) >= 120:
            score += 1.0
        elif len(s) >= 60:
            score += 0.5

        if tags:
            scored.append((score, {"line": s, "score": round(score, 2), "tags": tags}))

    scored.sort(key=lambda x: x[0], reverse=True)
    out, seen = [], set()
    for _, item in scored:
        if item["line"] in seen:
            continue
        seen.add(item["line"])
        out.append(item)
        if len(out) >= max_lines:
            break
    return out

def extract_iocs_from_suspicious(suspicious: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    urls, domains, ips, emails, reg, paths = set(), set(), set(), set(), set(), set()

    for item in suspicious or []:
        s = item.get("line", "")
        for m in RE_URL.findall(s): urls.add(m)
        for m in RE_IPV4.findall(s): ips.add(m)
        for m in RE_EMAIL.findall(s): emails.add(m)
        for m in RE_REG.findall(s): reg.add(m)
        for m in RE_WIN_PATH.findall(s): paths.add(m)
        for m in RE_POSIX_PATH.findall(s): paths.add(m)
        for m in RE_DOMAIN.findall(s): domains.add(m)

    return {
        "urls": sorted(urls)[:200],
        "domains": sorted(domains)[:200],
        "ips": sorted(ips)[:200],
        "emails": sorted(emails)[:200],
        "registry_paths": sorted(reg)[:200],
        "file_paths": sorted(paths)[:200],
    }

try:
    from custom_tools.ghidra_headless import ghidra_headless_summary  # type: ignore
except Exception:
    ghidra_headless_summary = None  # type: ignore

def _snip(s: str, n: int = 12000) -> str:
    s = s or ""
    return s[:n]

def build_evidence_pack(preflight: Dict[str, Any], options: Dict[str,Any] | None = None) -> Dict[str, Any]:
    kind = preflight.get("kind", "unknown")
    options = options or {} 

    import_text_parts = []
    if kind == "pe":
        import_text_parts.append((preflight.get("mandatory_objdump_pe_headers") or {}).get("stdout", ""))
        import_text_parts.append((preflight.get("mandatory_objdump_pe_dynamic") or {}).get("stdout", ""))
        import_text_parts.append((preflight.get("mandatory_radare2_info") or {}).get("stdout", ""))
        import_text_parts.append((preflight.get("mandatory_ghidra_malhaus") or {}).get("stdout",""))

        if options.get("use_ghidra"):
            import_text_parts.append((preflight.get("mandatory_ghidra_summary") or {}).get("stdout",""))

    elif kind == "elf":
        import_text_parts.append((preflight.get("mandatory_objdump_elf_dynamic") or {}).get("stdout", ""))
        import_text_parts.append((preflight.get("mandatory_readelf_all") or {}).get("stdout", ""))
        if options.get("use_ghidra"):
            import_text_parts.append((preflight.get("mandatory_ghidra_summary") or {}).get("stdout",""))

    elif kind == "office":
        import_text_parts.append((preflight.get("mandatory_oledump_details") or {}).get("stdout",""))
        import_text_parts.append((preflight.get("mandatory_oledump_list") or {}).get("stdout",""))
        import_text_parts.append((preflight.get("mandatory_olevba_json") or {}).get("stdout",""))
        import_text_parts.append((preflight.get("mandatory_oleobj_extract") or {}).get("stdout",""))
        import_text_parts.append((preflight.get("mandatory_rtfobj_extract") or {}).get("stdout",""))
        import_text_parts.append((preflight.get("mandatory_oledump_details") or {}).get("stdout",""))

    elif kind == "office_openxml":
        import_text_parts.append((preflight.get("mandatory_openxml_list") or {}).get("stdout",""))
        import_text_parts.append((preflight.get("mandatory_openxml_extract") or {}).get("stdout",""))
    elif kind == "lnk":
        import_text_parts.append((preflight.get("mandatory_lnk_analysis") or {}).get("stdout",""))
    elif kind == "pdf":
        import_text_parts.append((preflight.get("mandatory_pdf_analysis") or {}).get("stdout",""))
    elif kind in ("vbs", "hta", "ps1", "js", "shell"):
        import_text_parts.append(preflight.get("mandatory_script_content") or "")


    import_names = extract_import_names_from_text("\n".join(import_text_parts))

    suspicious = filter_suspicious_lines(
        strings_text=preflight.get("strings_preview", "") or "",
        import_names=import_names,
        max_lines=60,
    )

    extracted = (preflight.get("extraction") or {}).get("extracted", []) or []
    iocs = extract_iocs_from_suspicious(suspicious)
    
    def _s(key: str) -> str:
        """Get output snippet from a preflight tool result.
        Falls back to stderr when stdout is empty — some tools (e.g. rtfobj)
        write their analysis table to stderr rather than stdout."""
        r = preflight.get(key) or {}
        text = (r.get("stdout") or "").strip()
        if not text:
            text = (r.get("stderr") or "").strip()
        return _snip(text)

    def _add(d: dict, key: str, val: str) -> None:
        """Only add non-empty values to avoid sending blank keys to LLM."""
        if val and val.strip():
            d[key] = val

    low_level_snippets: Dict[str, str] = {}

    if kind == "pe":
        _add(low_level_snippets, "objdump_pe_headers",   _s("mandatory_objdump_pe_headers"))
        _add(low_level_snippets, "objdump_pe_dynamic",   _s("mandatory_objdump_pe_dynamic"))
        _add(low_level_snippets, "radare2_info",         _s("mandatory_radare2_info"))
        _add(low_level_snippets, "radare2_entry",        _s("mandatory_radare2_entry"))
        _add(low_level_snippets, "dotnet_analysis",      _s("mandatory_dotnet_analysis"))
        if options.get("use_ghidra"):
            _add(low_level_snippets, "ghidra_malhaus",   _s("mandatory_ghidra_malhaus"))

    elif kind == "elf":
        _add(low_level_snippets, "readelf_all",          _s("mandatory_readelf_all"))
        _add(low_level_snippets, "objdump_elf_dynamic",  _s("mandatory_objdump_elf_dynamic"))
        _add(low_level_snippets, "ldd_deps",             _s("mandatory_ldd_deps"))
        if options.get("use_ghidra"):
            _add(low_level_snippets, "ghidra_malhaus",   _s("mandatory_ghidra_malhaus"))

    elif kind == "office":
        _add(low_level_snippets, "oledump_list",         _s("mandatory_oledump_list"))
        _add(low_level_snippets, "oledump_details",      _s("mandatory_oledump_details"))
        _add(low_level_snippets, "olevba",               _s("mandatory_olevba_json"))
        _add(low_level_snippets, "oleobj_extract",       _s("mandatory_oleobj_extract"))
        _add(low_level_snippets, "rtfobj_extract",       _s("mandatory_rtfobj_extract"))

    elif kind == "office_openxml":
        _add(low_level_snippets, "openxml_list",         _s("mandatory_openxml_list"))
        _add(low_level_snippets, "openxml_extract",      _s("mandatory_openxml_extract"))

    elif kind == "msi":
        msi = preflight.get("mandatory_msi_extract") or {}
        files = msi.get("extracted_files") or []
        files_text = "\n".join(f"{f.get('path','')}  ({f.get('size',0)} bytes)" for f in files)
        _add(low_level_snippets, "msi_files",          files_text[:6000])
        _add(low_level_snippets, "msi_pe_strings",     (msi.get("pe_strings_preview") or "")[:6000])
        if msi.get("largest_pe"):
            _add(low_level_snippets, "msi_largest_pe", msi["largest_pe"])

    elif kind == "pdf":
        _add(low_level_snippets, "pdf_analysis", _s("mandatory_pdf_analysis"))

    elif kind == "lnk":
        _add(low_level_snippets, "lnk_analysis", _s("mandatory_lnk_analysis"))

    elif kind in ("vbs", "hta", "ps1", "js", "shell"):
        content = preflight.get("mandatory_script_content") or ""
        _add(low_level_snippets, "script_content", content[:12000])
    
    pack = {
        "kind": kind,
        "file_entropy": (preflight.get("entropy") or {}).get("entropy"),
        "import_name_sample": sorted(list(import_names))[:80],
        "suspicious_strings": suspicious,
        "extracted_payloads": extracted[:60],
        "iocs_deterministic": iocs,
        "low_level_snippets": low_level_snippets,
    }
    if preflight.get("analysis_note"):
        pack["analysis_note"] = preflight["analysis_note"]
    # Pass .NET capabilities to heuristics
    dotnet_result = preflight.get("mandatory_dotnet_analysis") or {}
    if dotnet_result.get("capabilities"):
        pack["dotnet_capabilities"] = dotnet_result["capabilities"]
    return pack
