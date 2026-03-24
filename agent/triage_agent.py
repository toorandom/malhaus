from pathlib import Path
from typing import Any, Dict
from shutil import which

from tools.cli_tools import ALL_TOOLS, byte_heatmap
from agent.custom_loader import load_custom_tools, tool_catalog
from agent.preflight import preflight
from agent.suspicious import build_evidence_pack
from agent.heuristics import heuristic_score_from_evidence
from agent.llm_loop import run_llm_tool_loop
from agent.postprocess import enforce_verdict
from agent.strings_llm import analyze_strings_llm
from agent.visualizations import compute_all as compute_visualizations
import config

MODEL_STRINGS = config.LLM_MODEL_STRINGS
MODEL_VERDICT = config.LLM_MODEL_VERDICT
MAX_TOOL_CALLS = config.LLM_MAX_TOOL_CALLS

TOOL_REGISTRY = {t.__name__: t for t in ALL_TOOLS}


# --- load custom tools from ./custom_tools ---
from pathlib import Path as _Path
_CUSTOM_DIR = _Path(__file__).resolve().parents[1] / "custom_tools"
_CUSTOM_TOOLS = load_custom_tools(_CUSTOM_DIR)
for _fn in _CUSTOM_TOOLS:
    TOOL_REGISTRY[getattr(_fn, "__name__", "tool")] = _fn

# Optional: tool catalog (name -> description) you can pass into llm_loop prompt later
ALL_TOOL_CATALOG = tool_catalog(list(TOOL_REGISTRY.values()))
def _snip_stdout(d: Dict[str, Any], n: int) -> str:
    """Return stdout up to n chars, falling back to stderr if stdout is empty.
    Some tools (e.g. rtfobj) write their analysis to stderr rather than stdout."""
    d = d or {}
    s = (d.get("stdout") or "").strip()
    if not s:
        s = (d.get("stderr") or "").strip()
    return s[:n]

def _fmt_section_entropy(pre: Dict[str, Any]) -> str:
    sec_data = (pre.get("mandatory_pe_section_entropy") or {})
    sections = sec_data.get("sections")
    if not sections:
        return sec_data.get("error", "not available")
    lines = []
    for s in sections:
        flag = " *** HIGH ENTROPY - PACKED/ENCRYPTED ***" if s.get("suspicious") else ""
        lines.append(
            f"  {s['name']:<12} entropy={s['entropy']:.4f}  "
            f"vsize={s['virtual_size']}  raw={s['raw_size']}  "
            f"exec={s['executable']}  write={s['writable']}{flag}"
        )
    return "\n".join(lines)


def build_mandatory_snips(pre: Dict[str, Any]) -> Dict[str, str]:
    snips: Dict[str, str] = {}
    if pre.get("analysis_note"):
        snips["ANALYSIS_WARNING"] = pre["analysis_note"]
    kind = pre.get("kind", "unknown")
    if kind == "pe":
        snips.update({
            "authenticode_verify_head": _snip_stdout(pre.get("authenticode_verify"), 4000),
            "objdump_x_head": _snip_stdout(pre.get("mandatory_objdump_pe_headers"), 4000),
            "objdump_p_head": _snip_stdout(pre.get("mandatory_objdump_pe_dynamic"), 4000),
            "r2_imports_head": _snip_stdout(pre.get("mandatory_radare2_info"), 4000),
            "r2_entry_head": _snip_stdout(pre.get("mandatory_radare2_entry"), 3000),
            "section_entropy": _fmt_section_entropy(pre),
            "dotnet_analysis": _snip_stdout(pre.get("mandatory_dotnet_analysis"), 4000),
            "binwalk": _snip_stdout(pre.get("mandatory_binwalk"), 3000),
        })
    elif kind == "elf":
        snips.update({
            "readelf_head": _snip_stdout(pre.get("mandatory_readelf_all"), 4000),
            "objdump_p_head": _snip_stdout(pre.get("mandatory_objdump_elf_dynamic"), 4000),
            "ldd_head": _snip_stdout(pre.get("mandatory_ldd_deps"), 2000),
            "binwalk": _snip_stdout(pre.get("mandatory_binwalk"), 3000),
        })
    elif kind == "lnk":
        snips["lnk_analysis"] = _snip_stdout(pre.get("mandatory_lnk_analysis"), 6000)
    elif kind == "pdf":
        snips["pdf_analysis"] = _snip_stdout(pre.get("mandatory_pdf_analysis"), 6000)
    elif kind == "office":
        snips["oledump_list"]   = _snip_stdout(pre.get("mandatory_oledump_list"), 3000)
        snips["olevba"]         = _snip_stdout(pre.get("mandatory_olevba_json"), 4000)
        snips["oledump_details"]= _snip_stdout(pre.get("mandatory_oledump_details"), 3000)
        snips["rtfobj_extract"] = _snip_stdout(pre.get("mandatory_rtfobj_extract"), 4000)
        snips["oleobj_extract"] = _snip_stdout(pre.get("mandatory_oleobj_extract"), 3000)
        _ghidra_pes = pre.get("mandatory_ghidra_extracted_pes") or {}
        if _ghidra_pes:
            snips["ghidra_extracted_pes"] = "\n\n".join(
                f"=== {name} ===\n{_snip_stdout(res, 3000)}" for name, res in _ghidra_pes.items()
            )[:6000]
    elif kind == "office_openxml":
        snips["openxml_list"] = _snip_stdout(pre.get("mandatory_openxml_list"), 3000)
        snips["openxml_extract"] = _snip_stdout(pre.get("mandatory_openxml_extract"), 3000)
        _ghidra_pes = pre.get("mandatory_ghidra_extracted_pes") or {}
        if _ghidra_pes:
            snips["ghidra_extracted_pes"] = "\n\n".join(
                f"=== {name} ===\n{_snip_stdout(res, 3000)}" for name, res in _ghidra_pes.items()
            )[:6000]
    elif kind == "msi":
        msi = pre.get("mandatory_msi_extract") or {}
        # Use the rich inventory from stdout if available, fall back to plain list
        if msi.get("stdout"):
            snips["msi_inventory"] = msi["stdout"][:4000]
        else:
            files = msi.get("extracted_files") or []
            snips["msi_inventory"] = "\n".join(
                f"{f.get('path','')}  ({f.get('size',0)} bytes)" for f in files
            )[:3000]
        if msi.get("largest_pe"):
            snips["msi_largest_pe"] = msi["largest_pe"]
        if msi.get("pe_strings_preview"):
            snips["msi_pe_strings"] = msi["pe_strings_preview"][:4000]
        msi_pe_analysis = pre.get("mandatory_msi_pe_analysis") or {}
        if msi_pe_analysis:
            pe_snip_parts = []
            for pe_name, pe_data in msi_pe_analysis.items():
                parts = [f"=== {pe_name} ({pe_data.get('path', '')}) ==="]
                auth = _snip_stdout(pe_data.get("authenticode"), 1500)
                if auth: parts.append(f"[authenticode]\n{auth}")
                hdrs = _snip_stdout(pe_data.get("pe_headers"), 1500)
                if hdrs: parts.append(f"[pe_headers]\n{hdrs}")
                ent = pe_data.get("pe_entropy") or {}
                sections = ent.get("sections")
                if sections:
                    sec_lines = []
                    for s in sections:
                        flag = " *** HIGH ENTROPY ***" if s.get("suspicious") else ""
                        sec_lines.append(f"  {s['name']:<12} entropy={s['entropy']:.4f}{flag}")
                    parts.append(f"[pe_entropy]\n" + "\n".join(sec_lines))
                dotnet = pe_data.get("dotnet_analysis")
                if dotnet:
                    dn_snip = _snip_stdout(dotnet, 1500)
                    if dn_snip:
                        parts.append(f"[dotnet_analysis]\n{dn_snip}")
                ghidra = pe_data.get("ghidra_malhaus")
                if ghidra:
                    gh_snip = _snip_stdout(ghidra, 2000)
                    if gh_snip:
                        parts.append(f"[ghidra]\n{gh_snip}")
                pe_snip_parts.append("\n".join(parts))
            snips["msi_pe_analysis"] = "\n\n".join(pe_snip_parts)[:6000]
    elif kind in ("vbs", "hta", "ps1", "js", "shell"):
        snips["script_content"] = (pre.get("mandatory_script_content") or "")[:6000]
    elif kind == "jar":
        snips["jar_manifest"]       = _snip_stdout(pre.get("mandatory_jar_manifest"), 3000)
        snips["jarsigner_verify"]   = _snip_stdout(pre.get("mandatory_jarsigner_verify"), 4000)
        snips["jar_class_list"]     = _snip_stdout(pre.get("mandatory_jar_class_list"), 4000)
        snips["jar_extract_inner"]  = _snip_stdout(pre.get("mandatory_jar_extract"), 4000)
        snips["javap_disasm"]       = _snip_stdout(pre.get("mandatory_javap_disasm"), 6000)
    return snips

def analyze(sample: str, options: Dict[str, Any] | None = None, progress_cb=None) -> Dict[str, Any]:
    import time
    _t0 = time.time()
    cb = progress_cb or (lambda msg: None)
    sample = str(Path(sample).resolve())

    pre = preflight(sample, options=options or {}, progress_cb=cb)
    kind = pre.get("kind", "unknown")

    if pre.get("analysis_abort"):
        reason = pre.get("analysis_abort_reason", "unknown")
        cb(f"Analysis aborted: {reason}")
        return {
            "sample": sample,
            "preflight": pre,
            "aborted": True,
            "abort_reason": reason,
            "verdict": {
                "action": "aborted",
                "risk_level": "unknown",
                "confidence": 0,
                "file_type": kind,
                "top_reasons": [f"Analysis aborted: {reason}. Resubmit with the correct archive password."],
                "iocs": {"urls": [], "domains": [], "ips": [], "emails": [],
                         "registry_paths": [], "file_paths": [], "mutexes": [],
                         "scheduled_tasks": [], "powershell_commands": []},
                "suspicious_strings": [],
                "embedded_payloads": [],
                "next_steps": ["Resubmit with the correct archive password."],
            },
            "strings_llm": {},
            "evidence_pack": {},
            "heuristics": {},
            "tool_results": {},
            "llm_calls": [],
            "analysis_seconds": round(time.time() - _t0, 1),
        }

    cb("LLM: strings analysis")
    strings_input = pre.get("strings_preview", "") or ""
    # For office files, raw strings from the binary are mostly hex-encoded OLE data
    # that gets filtered out. Augment with structured tool output that contains
    # readable strings (macro code, stream names, embedded object info).
    if kind == "office":
        def _s2(key: str) -> str:
            r = pre.get(key) or {}
            t = (r.get("stdout") or "").strip()
            if not t:
                t = (r.get("stderr") or "").strip()
            return t
        for _key in ("mandatory_olevba_json", "mandatory_oledump_list",
                     "mandatory_oledump_details", "mandatory_rtfobj_extract",
                     "mandatory_oleobj_extract"):
            _t = _s2(_key)
            if _t:
                strings_input += "\n" + _t[:3000]
    try:
        strings_llm = analyze_strings_llm(
            model=MODEL_STRINGS,
            kind=kind,
            file_entropy=(pre.get("entropy") or {}).get("entropy"),
            strings_preview=strings_input,
            max_chars=20000,
            progress_cb=cb,
        )
    except Exception as _e:
        strings_llm = {"error": f"strings_llm_crashed: {type(_e).__name__}: {_e}",
                       "strings_score": 0, "strings_risk_level": "unknown",
                       "strings_confidence": 0, "summary": "", "evidence": [], "iocs": {},
                       "_prompt_head": "", "_raw_output": str(_e)}

    cb("Building evidence pack")
    evidence_pack = build_evidence_pack(pre, options=options or {})
    cb("Heuristic scoring")
    heuristics = heuristic_score_from_evidence(evidence_pack, strings_llm)
    mandatory_snips = build_mandatory_snips(pre)

    cb("LLM: verdict loop")
    # If archive promoted an inner file, run tools on that file instead of the zip
    tool_sample = pre.get("effective_sample") or sample

    # Tools already run in preflight — LLM should not re-call these
    _MANDATORY_BY_KIND = {
        "pe":  {"authenticode_verify", "objdump_pe_headers", "objdump_pe_imports_dynamic",
                "radare2_quick_json", "radare2_entry_disasm", "pe_section_entropy",
                "floss_strings", "entropy_shannon", "sha256", "file_info",
                "upx_detect", "upx_unpack", "strings_ascii", "extract_payloads",
                "dotnet_analysis", "binwalk_scan"},
        "elf": {"readelf_all", "objdump_elf_dynamic", "ldd_deps",
                "floss_strings", "entropy_shannon", "sha256", "file_info",
                "upx_detect", "upx_unpack", "strings_ascii", "extract_payloads",
                "binwalk_scan"},
        "office": {"oledump_list", "olevba_json", "oleobj_extract", "rtfobj_extract",
                   "oledump_details", "strings_ascii", "extract_payloads", "entropy_shannon",
                   "sha256", "file_info"},
        "office_openxml": {"openxml_list", "openxml_extract", "strings_ascii",
                           "extract_payloads", "entropy_shannon", "sha256", "file_info"},
        "pdf":   {"pdf_analysis", "strings_ascii", "extract_payloads", "entropy_shannon", "sha256", "file_info"},
        "lnk":   {"lnk_analysis", "strings_ascii", "extract_payloads", "entropy_shannon", "sha256", "file_info"},
        "msi":   {"msi_extract", "strings_ascii", "extract_payloads", "entropy_shannon", "sha256", "file_info"},
        "jar":   {"jar_manifest", "jarsigner_verify", "jar_class_list", "jar_extract_inner", "javap_disasm",
                  "strings_ascii", "extract_payloads", "entropy_shannon", "sha256", "file_info"},
    }
    already_ran = _MANDATORY_BY_KIND.get(kind, {"entropy_shannon", "sha256", "file_info", "strings_ascii", "extract_payloads"})
    # If Ghidra ran in preflight, don't let the LLM re-call it
    if options and options.get("use_ghidra") and "mandatory_ghidra_malhaus" in pre:
        already_ran = already_ran | {"ghidra_malhaus"}

    # Only offer the LLM tools that make sense for the current file type.
    # Prevents the LLM wasting its tool budget on irrelevant tools
    # (e.g. calling script_content on a PE, or PE tools on an office doc).
    _SUPPLEMENTARY_BY_KIND = {
        "pe":            {"ssdeep_hash", "pe_overlay_info", "pe_imphash", "readpe_all", "pesec",
                          "objdump_pe_headers", "objdump_pe_imports_dynamic",
                          "radare2_quick_json", "radare2_entry_disasm", "ghidra_malhaus"},
        "elf":           {"ssdeep_hash", "readelf_all", "objdump_elf_dynamic", "ldd_deps",
                          "objdump_elf_disasm", "ghidra_malhaus"},
        "office":        {"ssdeep_hash", "olevba_json", "oledump_list", "oledump_details",
                          "oleobj_extract", "rtfobj_extract",
                          "script_content", "js_beautify", "strings_ascii", "entropy_shannon"},
        "office_openxml":{"ssdeep_hash", "olevba_json", "oledump_list", "oledump_details",
                          "openxml_list", "openxml_extract", "rtfobj_extract", "oleobj_extract",
                          "script_content", "js_beautify", "strings_ascii", "entropy_shannon"},
        "pdf":           {"ssdeep_hash", "pdf_analysis"},
        "lnk":           {"ssdeep_hash", "lnk_analysis", "exiftool_lnk", "lecmd_lnk"},
        # MSI: LLM uses path field to run PE tools on any extracted file
        "msi":           {"ssdeep_hash", "strings_ascii", "entropy_shannon",
                          "objdump_pe_headers", "objdump_pe_imports_dynamic",
                          "pe_section_entropy", "readpe_all", "pesec",
                          "authenticode_verify"},
        "jar":           {"ssdeep_hash", "jar_manifest", "jarsigner_verify", "jar_class_list",
                          "javap_disasm", "jar_extract_inner",
                          "strings_ascii", "entropy_shannon", "binwalk_scan"},
        "ps1":           {"ssdeep_hash", "script_content", "shell_lint"},
        "vbs":           {"ssdeep_hash", "script_content"},
        "hta":           {"ssdeep_hash", "script_content"},
        "js":            {"ssdeep_hash", "script_content", "js_beautify"},
        "shell":         {"ssdeep_hash", "script_content", "shell_lint"},
        # Archive that could not be promoted — LLM can run tools on inner files
        "archive":       {"ssdeep_hash", "archive_extract", "strings_ascii",
                          "entropy_shannon", "objdump_pe_headers",
                          "objdump_pe_imports_dynamic", "pe_section_entropy"},
        # Unknown type — offer generic inspection tools only
        "unknown":       {"ssdeep_hash", "file_info", "strings_ascii", "entropy_shannon"},
    }
    allowed = _SUPPLEMENTARY_BY_KIND.get(kind, set(TOOL_REGISTRY.keys()))
    # Filter out tools whose underlying binary is not installed so the LLM never
    # wastes a tool call on something that will immediately fail.
    _BINARY_DEPS = {
        "ssdeep_hash": "ssdeep",
        "ghidra_malhaus": "ghidra",
        "lecmd_lnk": "lecmd",
        "js_beautify": "js-beautify",
        "shell_lint": "bash",
    }
    supplementary_registry = {
        k: v for k, v in TOOL_REGISTRY.items()
        if k not in already_ran
        and k in allowed
        and (which(_BINARY_DEPS[k]) is not None if k in _BINARY_DEPS else True)
    }
    supplementary_catalog = tool_catalog(list(supplementary_registry.values()))

    verdict_raw, tool_results, llm_calls = run_llm_tool_loop(
        model=MODEL_VERDICT,
        sample_path=tool_sample,
        kind=kind,
        evidence_pack=evidence_pack,
        strings_llm=strings_llm,
        heuristics=heuristics,
        mandatory_snips=mandatory_snips,
        tool_registry=supplementary_registry,
        max_tool_calls=MAX_TOOL_CALLS,
        tool_catalog=supplementary_catalog,
        fallback_model=MODEL_STRINGS,
        progress_cb=cb,
        )

    cb("Finalizing verdict")
    verdict = enforce_verdict(verdict_raw, evidence_pack, heuristics, pre, strings_llm=strings_llm)

    cb("Generating byte heatmap")
    heatmap = byte_heatmap(tool_sample)

    cb("Generating visualizations")
    visualizations = compute_visualizations(tool_sample, model=MODEL_VERDICT, progress_cb=cb)

    return {
        "sample": sample,
        "promoted_sample": tool_sample if tool_sample != sample else None,
        "preflight": pre,
        "strings_llm": strings_llm,
        "evidence_pack": evidence_pack,
        "heuristics": heuristics,
        "tool_results": tool_results,
        "llm_calls": llm_calls,
        "verdict": verdict,
        "byte_heatmap_b64": heatmap.get("b64") if heatmap.get("ok") else None,
        "visualizations": visualizations,
        "analysis_seconds": round(time.time() - _t0, 1),
        "llm_provider":  config.LLM_PROVIDER or "gemini",
        "model_strings": MODEL_STRINGS,
        "model_verdict": MODEL_VERDICT,
        "llm_endpoint":  config.LLM_ENDPOINT or "",
    }
