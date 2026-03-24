import json
import re
from typing import Any, Dict, List, Tuple, Optional

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from agent.llm_factory import get_llm


def _clean_fences(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.IGNORECASE)
        s = re.sub(r"\s*```$", "", s)
    return s.strip()


def _unwrap_text(payload: Any) -> Optional[str]:
    # Handles: [{"type":"text","text":"{...}"}] and {"text":"{...}"}
    if isinstance(payload, dict):
        if isinstance(payload.get("text"), str):
            return payload["text"]
        if isinstance(payload.get("content"), str):
            return payload["content"]
        return None

    if isinstance(payload, list) and payload:
        first = payload[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            return first["text"]
        if len(payload) == 1 and isinstance(payload[0], str):
            return payload[0]
    return None


def _extract_first_json_object(s: str) -> str:
    """
    Return the first top-level {...} JSON object from s using balanced-brace
    scanning.  Correctly handles nested objects, arrays, and string literals
    (including escaped quotes), so it stops at the real closing brace rather
    than the last } in the whole string.

    If the LLM appends commentary or a second JSON block after the verdict,
    this extracts only the first object — avoiding the greedy-regex failure
    mode where json.loads is given the over-extended match.
    """
    start = s.find("{")
    if start == -1:
        return ""
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s[start:], start):
        if esc:
            esc = False
            continue
        if in_str:
            if ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return s[start : i + 1]
    return ""


def _parse_any_json_object(raw: str) -> Dict[str, Any]:
    raw = (raw or "").strip()

    def _first_dict(v):
        if isinstance(v, dict):
            return v
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    return item
        return None

    # 1) Try: raw is JSON wrapper or JSON dict
    try:
        outer = json.loads(_clean_fences(raw))
        inner = _unwrap_text(outer)
        if inner:
            d = _first_dict(json.loads(_clean_fences(inner)))
            if d is not None:
                return d
        d = _first_dict(outer)
        if d is not None:
            return d
    except Exception:
        pass

    cleaned = _clean_fences(raw)

    # 2) Balanced-brace extraction — handles trailing commentary / second JSON blocks
    candidate = _extract_first_json_object(cleaned)
    if candidate:
        try:
            d = _first_dict(json.loads(candidate))
            if d is not None:
                return d
        except Exception:
            pass

    # 3) Non-greedy regex (small self-contained objects)
    m = re.search(r"\{.*?\}", cleaned, flags=re.DOTALL)
    if m:
        try:
            d = _first_dict(json.loads(m.group(0)))
            if d is not None:
                return d
        except Exception:
            pass

    raise ValueError("no_json_object_found")


def _ui_safe_fallback(kind: str, heuristics: Dict[str, Any], raw: str, reason: str = "parse_failed") -> Dict[str, Any]:
    if reason == "timeout":
        msg = "LLM verdict timed out on all retry attempts; showing heuristic-only fallback."
    elif reason == "empty_response":
        msg = "LLM returned an empty response (possible safety block); showing heuristic-only fallback."
    else:
        msg = "LLM output could not be parsed; showing heuristic-only fallback."
    return {
        "action": "final",
        "file_type": kind,
        "risk_level": heuristics.get("risk_hint", "unknown"),
        "confidence": int(heuristics.get("score", 0) or 0),
        "top_reasons": [msg, "Raw LLM output is available in logs."],
        "iocs": {
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": [],
            "registry_paths": [],
            "file_paths": [],
            "mutexes": [],
            "scheduled_tasks": [],
            "powershell_commands": [],
        },
        "suspicious_strings": [],
        "embedded_payloads": [],
        "next_steps": [],
        "_error": f"llm_{reason}",
        "_raw_head": (raw or "")[:1200],
    }


def _content_filter_final_verdict(
    model: str,
    kind: str,
    heuristics: Dict[str, Any],
    strings_llm: Dict[str, Any],
    evidence_pack: Dict[str, Any],
    tool_results: Dict[str, Any],
    llm_calls: Optional[List[Dict[str, Any]]] = None,
    progress_cb=None,
) -> Optional[Dict[str, Any]]:
    """
    When Azure content filter blocks all normal verdict calls, build a minimal
    metadata-only prompt (no file content) and make one final clean LLM call.
    Uses only structured facts: heuristics, strings summary, tool names + key findings.
    Returns parsed verdict dict or None if this also fails.
    """
    cb = progress_cb or (lambda msg: None)

    # Summarise tool_results as key metadata only — no raw file content.
    # Script/content tools (script_content, js_beautify) are the ones that triggered
    # the filter; skip their content entirely but note they were called and filtered.
    # For structural analysis tools (rtfobj_extract, oledump, etc.) extract key signals.
    _CONTENT_TOOLS = {"script_content", "js_beautify", "strings_ascii", "floss_strings"}
    _SIGNAL_RE = re.compile(
        r"(Filename:\s*'[^']+'|EXECUTABLE FILE|CVE-\d{4}-\d+|class name:.*|"
        r"Possibly an exploit|OLE Package|AutoOpen|AutoExec|Shell|WScript|"
        r"CreateObject|powershell|cmd\.exe|\.exe|\.dll|\.js|\.vbs|"
        r"format_id:.*Embedded|data size:\s*\d+|MD5\s*=\s*[0-9a-fA-F]+)",
        re.IGNORECASE,
    )

    tool_findings: list[str] = []
    for key, result in (tool_results or {}).items():
        tool_name = key.split("::")[0]
        file_label = key.split("::")[-1] if "::" in key else ""
        if not isinstance(result, dict):
            continue
        if tool_name in _CONTENT_TOOLS:
            # Don't send file content — note it was called and filtered
            label = f" on {file_label}" if file_label else ""
            tool_findings.append(
                f"- {tool_name}{label}: [content blocked by provider content filter — "
                "this strongly indicates the file contains dangerous/malicious code]"
            )
            continue
        stdout = (result.get("stdout") or "")
        # Extract signal lines (filenames, CVEs, EXECUTABLE flags, etc.)
        signals = _SIGNAL_RE.findall(stdout)
        if signals:
            sig_str = " | ".join(dict.fromkeys(s.strip() for s in signals[:15]))
            tool_findings.append(f"- {tool_name}: {sig_str}")
        elif stdout:
            # Fall back to first 300 chars if no signal lines matched
            snippet = stdout[:300].replace("\n", " ").strip()
            tool_findings.append(f"- {tool_name}: {snippet}")

    tool_block = "\n".join(tool_findings) if tool_findings else "(no tool results)"
    h_score  = heuristics.get("score", 0)
    h_hint   = heuristics.get("risk_hint", "unknown")
    sl_risk  = (strings_llm or {}).get("strings_risk_level", "unknown")
    sl_sum   = (strings_llm or {}).get("summary", "")[:600]
    sl_ev    = "\n".join(
        f"- {e.get('tag','')}: {e.get('description','')[:120]}"
        for e in ((strings_llm or {}).get("evidence") or [])[:8]
    )

    prompt = f"""You are a malware analyst. Produce a final verdict JSON for the file described below.

IMPORTANT: The previous analysis session was interrupted because the provider content filter
blocked tool output — this is itself a strong indicator that the file contains malicious code.
risk_level MUST be at least "suspicious" (likely "likely_malware").

File type: {kind}
Heuristic score: {h_score}/100  hint: {h_hint}
Strings analysis risk: {sl_risk}
Strings summary: {sl_sum}
Strings evidence:
{sl_ev}

Tool findings (metadata only):
{tool_block}

Content filter signal: provider content filter blocked analysis of an embedded payload —
this indicates the file contains dangerous/exploit/dropper code.

Return ONLY this JSON (no markdown):
{{"action":"final","file_type":"{kind}","risk_level":"benign|suspicious|likely_malware|malware","confidence":0-100,"top_reasons":["..."],"iocs":{{"urls":[],"domains":[],"ips":[],"emails":[],"registry_paths":[],"file_paths":[],"mutexes":[],"scheduled_tasks":[],"powershell_commands":[]}},"suspicious_strings":[],"embedded_payloads":[],"next_steps":[]}}"""

    cb("LLM: content-filter-safe final verdict call (metadata only)…")
    try:
        llm = get_llm(model)
        resp = llm.invoke([HumanMessage(content=prompt)])
        raw = resp.content if isinstance(resp.content, str) else json.dumps(resp.content)
        result = _parse_any_json_object(raw)
        if llm_calls is not None:
            llm_calls.append({
                "iteration": "cf_recovery",
                "prompt": prompt[:80000],
                "raw_output": raw[:8000],
                "failed": False,
                "note": "content-filter-safe metadata-only recovery call",
            })
        return result
    except Exception as e:
        cb(f"Content-filter-safe verdict call also failed: {e}")
        if llm_calls is not None:
            llm_calls.append({
                "iteration": "cf_recovery",
                "prompt": prompt[:80000],
                "raw_output": f"FAILED: {e}",
                "failed": True,
                "note": "content-filter-safe metadata-only recovery call",
            })
        return None


def run_llm_tool_loop(
    model: str,
    sample_path: str,
    kind: str,
    evidence_pack: Dict[str, Any],
    strings_llm: Dict[str, Any],
    heuristics: Dict[str, Any],
    mandatory_snips: Dict[str, str],
    tool_registry: Dict[str, Any],
    max_tool_calls: int = 6,
    tool_catalog: Optional[List[Dict[str, str]]] = None,
    fallback_model: Optional[str] = None,
    progress_cb=None,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]:
    cb = progress_cb or (lambda msg: None)
    tool_results: Dict[str, Any] = {}
    llm_calls: List[Dict[str, Any]] = []
    strings_score = int((strings_llm or {}).get("strings_score", 0) or 0)
    _thinking_disabled = False
    _content_filter_fired = False   # tracks if any tool result was blocked by content filter
    _content_filter_count = 0       # number of times filter has fired (cap retries)
    _parse_errors = 0               # number of JSON parse failures — allows one retry

    tool_catalog_block = "(no tools)"
    if tool_catalog:
        try:
            tool_catalog_block = "\n".join(
                f"- {t.get('name')}: {t.get('description')}" for t in tool_catalog
            )
        except Exception:
            tool_catalog_block = "(unavailable)"

    system_prompt = f"""You are an expert malware reverse engineer and threat analyst performing static triage.
Your job: analyse the provided evidence and give a definitive verdict. Be decisive — "unknown" is a last resort.

TOOL CALLING:
You may call up to {max_tool_calls} tools to gather more evidence before giving your verdict.
To call a tool respond with STRICT JSON:
  {{"action":"call_tool","tool":"<tool_name>","reason":"<why you need it>"}}
To run a tool on an inner/extracted file instead of the main sample, add an optional "path" field
with the absolute path you want to analyse (e.g. an RTF found inside a DOCX, a PE found inside an archive):
  {{"action":"call_tool","tool":"rtfobj_extract","path":"/app/extracted/.../word/anage.rtf","reason":"analyse embedded RTF"}}
Only use "path" for files you have already seen in a previous tool result. Do not guess paths.
When you have enough evidence OR have used all tool calls, give your final verdict:
  {{"action":"final","file_type":"{kind}","risk_level":"benign|suspicious|likely_malware|unknown","confidence":0-100,"top_reasons":[...],"iocs":{{"urls":[],"domains":[],"ips":[],"emails":[],"registry_paths":[],"file_paths":[],"mutexes":[],"scheduled_tasks":[],"powershell_commands":[]}},"suspicious_strings":[{{"line":"...","why":"...","tags":["..."]}}],"embedded_payloads":[],"next_steps":[]}}

Available tools:
{tool_catalog_block}

FILE-TYPE GUIDANCE:
- pe: Check authenticode_verify_head for signature status (VERIFIED=signed, NO SIGNATURE=unsigned). Examine imports for suspicious API patterns (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, etc.). High section entropy = packed/encrypted.
- elf: Check dynamic imports, POSIX syscalls, network functions, dropped file paths.
- lnk: Windows Shortcut files are a common malware delivery vector. ALWAYS call exiftool_lnk and lecmd_lnk (if available) to obtain structured target path, arguments, working directory, and metadata before reaching a verdict.
- office/office_openxml: ALWAYS call at least one supplementary tool before verdict — never return a final verdict on the first call without tool use. Check olevba for VBA macros, AutoOpen/AutoExec triggers, Shell/WScript calls, base64 blobs, external URL references. If the openxml_list or openxml_extract output (in low_level_tool_outputs) shows ANY .rtf files, you MUST call rtfobj_extract on each extracted RTF path before producing a verdict — this is non-negotiable. When rtfobj_extract output includes a "[Extracted files saved to disk:]" section, run script_content or js_beautify (for .js/.vbs/.ps1 files) or strings_ascii (for binaries) on EACH listed path. NEVER call script_content on .rtf, .docx, .doc, .xlsx, .zip, or any binary container file — those are not text scripts and will produce garbage output. Only call script_content on plain text script files (.js, .vbs, .ps1, .hta, .sh, .bat). If it reveals embedded .pdf files, run pdf_analysis on them. If it reveals .exe/.dll, run strings_ascii on them.
- msi: msi_inventory shows ALL extracted files with type, size, entropy. msi_authenticode/msi_pe_headers/msi_pe_entropy are pre-run on the largest PE — check signing status, suspicious imports (VirtualAlloc, CreateRemoteThread, WinExec, URLDownloadToFile etc.), and high-entropy sections. Use the "path" field to run targeted tools on OTHER suspicious files — e.g. strings_ascii/objdump_pe_headers/pe_section_entropy on high-entropy secondaries. Analyze ALL PEs, not just the largest — MSI droppers often hide payloads in secondary files.
- pdf: Check for /JavaScript, /OpenAction, /Launch, /EmbeddedFile, suspicious URI streams.
- jar: Java archives (JAR/WAR/EAR). jar_manifest shows Main-Class (entry point) and permissions. jarsigner_verify shows signing status — unsigned JARs are suspicious. jar_class_list shows all classes and resources. javap_disasm disassembles the main class and suspicious classes — look for Runtime.exec(), ProcessBuilder, socket connections, ClassLoader.defineClass(), reflection, URLClassLoader, base64 decode, file I/O to temp dirs. jar_extract_inner inventories embedded PE/ELF binaries, nested JARs, and scripts. Use 'path' field to run strings_ascii or binwalk_scan on any suspicious extracted file.
- ps1/vbs/hta/js/shell: Script files — analyse content directly. Obfuscation, encoded payloads, downloads, persistence = malicious.

RULES:
- For office_openxml files: if the initial context shows .rtf files inside the package, you MUST call rtfobj_extract before producing a final verdict. Skipping this tool on the first iteration is not allowed.
- If file_type=="pe": base signature statements ONLY on authenticode_verify_head. VERIFIED/OK=signed, NO SIGNATURE=unsigned, failure=invalid.
- UPX packing is not necessarily evidence of malware — many legitimate applications use it for size reduction. It is a contributing signal, not a conclusion. Weight it alongside the unpacked content: if the promoted (unpacked) file shows suspicious imports, strings, or behaviour, UPX adds to the suspicion; if the unpacked file looks clean, UPX alone should not tip the verdict toward malicious.
- If strings_llm.strings_score>=35 you MUST NOT return risk_level="unknown" — use "suspicious" at minimum.
- If a LOLBin (powershell, cmd, mshta, wscript, certutil, scp, curl, bitsadmin, regsvr32, rundll32) appears in a lnk/script context, treat it as suspicious or likely_malware depending on arguments.
- confidence must reflect your actual certainty (0=no idea, 100=certain). Do NOT return confidence=0 if you have any evidence.
- No markdown. JSON only.""".strip()

    # Strip debug-only fields from strings_llm before sending to LLM
    strings_llm_clean = {k: v for k, v in (strings_llm or {}).items()
                         if k not in ("_raw_output", "_prompt_head")}

    # evidence_pack.low_level_snippets duplicates mandatory_snips — send only one copy
    evidence_pack_clean = {k: v for k, v in (evidence_pack or {}).items()
                           if k != "low_level_snippets"}

    # Collapse repetitive-character lines in suspicious_strings before sending.
    # The same patterns that stall the strings_llm (AAAA×80, QQQQ×60 etc. from
    # packed sections) are carried through evidence_pack and trigger the same
    # LLM content-safety scanner, causing the verdict loop to time out too.
    def _collapse_rep(line: str, threshold: float = 0.70, min_len: int = 18) -> str:
        if len(line) < min_len:
            return line
        from collections import Counter as _C
        top_ch, top_n = _C(line).most_common(1)[0]
        if top_n / len(line) >= threshold:
            return f"[rep: {repr(top_ch)}×{len(line)}]"
        return line

    if isinstance(evidence_pack_clean.get("suspicious_strings"), list):
        evidence_pack_clean = dict(evidence_pack_clean)
        evidence_pack_clean["suspicious_strings"] = [
            {**s, "line": _collapse_rep(s.get("line", ""))}
            if isinstance(s, dict) else s
            for s in evidence_pack_clean["suspicious_strings"]
        ]

    initial_context = json.dumps({
        "file": sample_path,
        "kind": kind,
        "heuristics": heuristics,
        "strings_llm": strings_llm_clean,
        "evidence_pack": evidence_pack_clean,
        "low_level_tool_outputs": mandatory_snips,
        "available_tools": sorted(list(tool_registry.keys())),
    }, ensure_ascii=False)[:120000]

    cb(f"Initial context: {len(initial_context):,} chars ({len(initial_context.encode('utf-8')):,} bytes)")

    messages: List = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=initial_context),
    ]

    verdict: Optional[Dict[str, Any]] = None
    _force_verdict = False  # set True after a cached-tool call to end the loop

    # Detect containers whose inner files MUST be analysed before a verdict is accepted.
    # Key: tool name that must appear in tool_results; value: human-readable reason.
    _required_tools: Dict[str, str] = {}
    if kind == "office_openxml":
        _ctx = initial_context.lower()
        if ".rtf" in _ctx:
            _required_tools["rtfobj_extract"] = (
                "openxml package contains embedded .rtf file(s) — rtfobj_extract MUST be called first"
            )

    for iteration in range(max_tool_calls + 1):
        is_last = (iteration == max_tool_calls) or _force_verdict
        if is_last:
            messages.append(HumanMessage(
                content="You have reached the maximum tool calls. You MUST give your final verdict now. "
                        "Respond with STRICT JSON only, action='final'."
            ))

        payload_bytes = sum(
            len((m.content if isinstance(m.content, str) else json.dumps(m.content)).encode("utf-8"))
            for m in messages
        )
        _n_tool_results = len(tool_results)
        if is_last:
            _call_desc = "forced final verdict"
        elif iteration == 0:
            _call_desc = f"initial verdict ({kind}, {len(tool_registry)} tools available)"
        else:
            _call_desc = f"follow-up after {_n_tool_results} tool result{'s' if _n_tool_results != 1 else ''}"
        cb(f"LLM call #{iteration + 1} — {_call_desc} — {payload_bytes:,} bytes")
        import time as _time
        import threading as _threading
        import config as _config
        _t0 = _time.time()
        last_exc = None
        resp = None
        _current_model = model
        for _attempt in range(3):
            # On a timeout retry: switch to fallback model (no mandatory thinking)
            # so the user isn't blocked indefinitely by the thinking model.
            if _attempt > 0 and isinstance(last_exc, TimeoutError) and fallback_model and _current_model != fallback_model:
                _current_model = fallback_model
                _thinking_disabled = True
                cb(f"LLM call #{iteration + 1} — switching to a faster model for performance")
            # Fresh client on every attempt — ensures a new HTTP connection rather
            # than reusing a stalled socket from a previous timed-out request.
            llm = get_llm(_current_model)

            _attempt_t0 = _time.time()
            _done = _threading.Event()
            def _ping(_t0=_attempt_t0, _it=iteration + 1):
                while not _done.wait(10):
                    cb(f"LLM call #{_it} still working… ({_time.time() - _t0:.0f}s)")
            _pt = _threading.Thread(target=_ping, daemon=True)
            _pt.start()

            # Thread-based timeout: provider-level timeouts only guard connection
            # setup, not streaming reads — a stalled response hangs indefinitely.
            _result: list = [None]
            _err: list = [None]
            def _do(_result=_result, _err=_err, _llm=llm):
                try:
                    _result[0] = _llm.invoke(messages)
                except Exception as _e:
                    _err[0] = _e
            _worker = _threading.Thread(target=_do, daemon=True)
            _worker.start()
            _worker.join(timeout=_config.LLM_TIMEOUT)

            _done.set()

            if _worker.is_alive():
                last_exc = TimeoutError(
                    f"LLM call #{iteration + 1} timed out after {_config.LLM_TIMEOUT}s "
                    f"({payload_bytes:,} bytes — likely server-side stall)"
                )
            elif _err[0]:
                last_exc = _err[0]
            else:
                resp = _result[0]
                # Empty content list means the model returned no usable text
                # (safety block, interrupted thinking, or empty server response).
                # Treat it as a retryable error rather than silently failing to parse.
                if isinstance(getattr(resp, "content", None), list) and not resp.content:
                    last_exc = ValueError(
                        f"LLM call #{iteration + 1} returned empty content []"
                    )
                else:
                    last_exc = None

            if last_exc is None:
                break

            # Record failed attempt in debug so the report shows what was sent
            last_human_fail = next(
                (m.content if isinstance(m.content, str) else json.dumps(m.content)
                 for m in reversed(messages) if isinstance(m, HumanMessage)),
                ""
            )
            is_timeout = isinstance(last_exc, TimeoutError)
            exc_name = type(last_exc).__name__
            llm_calls.append({
                "iteration": iteration,
                "prompt": last_human_fail[:80000],
                "raw_output": f"{'TIMEOUT' if is_timeout else 'ERROR'} (attempt {_attempt + 1}/3): {last_exc}",
                "failed": True,
            })

            exc_str = str(last_exc)
            # Azure/OpenAI content filter: the last tool result contained malware content
            # that was blocked. Strip that message from context and retry with a note —
            # the LLM can still produce a verdict based on metadata from earlier calls.
            if "content_filter" in exc_str.lower() or "content management policy" in exc_str.lower():
                _content_filter_fired = True
                _content_filter_count += 1
                cb(f"LLM call #{iteration + 1} blocked by content filter — content is likely malicious; scheduling fresh verdict call")

                if _content_filter_count >= 2:
                    # Still firing after stripping — try one final content-safe LLM call
                    # with ONLY metadata (no file content), then fall to heuristic if that fails.
                    cb(f"Content filter fired {_content_filter_count}x — trying metadata-only verdict call")
                    _cf_verdict = _content_filter_final_verdict(
                        model=model, kind=kind, heuristics=heuristics,
                        strings_llm=strings_llm, evidence_pack=evidence_pack,
                        tool_results=tool_results, llm_calls=llm_calls, progress_cb=cb,
                    )
                    if _cf_verdict is not None:
                        verdict = _cf_verdict
                        # Ensure minimum risk level since filter fired
                        _RISK_ORDER_CF = ["unknown", "benign", "suspicious", "likely_malware", "malware"]
                        if _RISK_ORDER_CF.index(verdict.get("risk_level","unknown")) < _RISK_ORDER_CF.index("suspicious"):
                            verdict["risk_level"] = "suspicious"
                        verdict.setdefault("top_reasons", []).insert(
                            0, "Provider content filter blocked analysis of embedded payload — file contains dangerous/malicious code."
                        )
                    else:
                        cb(f"Metadata-only verdict also failed — using heuristic fallback")
                        verdict = _ui_safe_fallback(kind, heuristics, f"content_filter_{_content_filter_count}x", reason="parse_failed")
                        verdict.setdefault("top_reasons", []).insert(
                            0, "Provider content filter blocked analysis of embedded payload — file contains dangerous/malicious code."
                        )
                    last_exc = RuntimeError(f"content_filter_repeated_{_content_filter_count}x")
                    break

                # Strip ALL tool-result HumanMessages AND intermediate AIMessages —
                # AIMessages from earlier iterations may contain LLM analysis of malicious
                # content which re-triggers the filter even after tool results are removed.
                # Keep: SystemMessage (index 0), initial HumanMessage (index 1).
                # Replace: all subsequent messages with a single compact filter note.
                _filter_note = "[content filtered — file contains dangerous code]"
                _new_messages = messages[:2]  # system prompt + initial context only
                _new_messages.append(HumanMessage(
                    content="[SYSTEM: Prior tool results were BLOCKED by provider content filter. "
                            "Produce final verdict based on initial context above only. "
                            "risk_level must be at least 'suspicious'. No tool calls.]"
                ))
                messages = _new_messages

                last_exc = None
                _force_verdict = True  # ensure next outer iteration is a final verdict call
                break  # exit attempt loop — outer loop will run a fresh LLM call

            # BadRequestError (4xx) is a client-side error — retrying the identical
            # request will always fail. Break immediately so we fall back to heuristics.
            if "BadRequest" in exc_name or "invalid_argument" in exc_str.lower():
                cb(f"LLM call #{iteration + 1} failed with {exc_name} (context too large or invalid request) — skipping retries")
                break

            retry_delay = 5 * (_attempt + 1) if is_timeout else 2 * (_attempt + 1)
            cb(f"LLM call #{iteration + 1} {'timeout' if is_timeout else 'transient error'} "
               f"(attempt {_attempt + 1}/3): {type(last_exc).__name__} — retrying in {retry_delay}s…")
            _time.sleep(retry_delay)

        if last_exc is not None:
            if verdict is not None:
                # Verdict was already set by the content-filter path — just stop iterating.
                break
            # All retries exhausted — fall back to heuristic-only verdict instead of
            # raising and losing all the preflight/heuristics work done so far.
            cb(f"LLM call #{iteration + 1} failed after all retries — using heuristic fallback")
            _reason = "timeout" if isinstance(last_exc, TimeoutError) else "parse_failed"
            verdict = _ui_safe_fallback(kind, heuristics, f"all_retries_failed: {last_exc}", reason=_reason)
            break

        if resp is None:
            if _content_filter_fired and last_exc is None:
                # Content filter fired once, messages cleaned, _force_verdict=True.
                # Continue outer loop for a fresh verdict LLM call (not heuristic fallback).
                cb(f"LLM call #{iteration + 1} — content filter handled; running fresh verdict call")
                continue
            # Either genuine failure or content filter gave up after max retries.
            cb(f"LLM call #{iteration + 1} — no response — using heuristic fallback")
            verdict = _ui_safe_fallback(kind, heuristics, "no_response", reason="parse_failed")
            break

        _elapsed = _time.time() - _t0
        cb(f"LLM call #{iteration + 1} completed in {_elapsed:.1f}s")
        raw = resp.content if isinstance(resp.content, str) else json.dumps(resp.content)

        # Unwrap Gemini's [{"type":"text","text":"...","extras":{...}}] envelope for clean display.
        # extras contains provider-internal signing metadata — strip it before storing.
        if raw.strip().startswith("["):
            try:
                items = json.loads(raw)
                decoded = _unwrap_text(items)
                if decoded:
                    display_output = decoded
                else:
                    # Can't unwrap to plain text — at least strip extras noise
                    cleaned = [{k: v for k, v in item.items() if k != "extras"}
                               if isinstance(item, dict) else item for item in items]
                    display_output = json.dumps(cleaned)
            except Exception:
                display_output = raw
        else:
            display_output = raw

        # Store last human message as the prompt shown in debug (skip system prompt)
        last_human = next(
            (m.content if isinstance(m.content, str) else json.dumps(m.content)
             for m in reversed(messages) if isinstance(m, HumanMessage)),
            ""
        )
        llm_calls.append({
            "iteration": iteration,
            "prompt": last_human[:80000],
            "raw_output": display_output[:20000],
        })

        try:
            parsed = _parse_any_json_object(raw)
        except Exception as _parse_exc:
            _parse_errors += 1
            cb(f"LLM call #{iteration + 1} — JSON parse failed ({_parse_exc}); "
               f"{'falling back' if is_last or _parse_errors >= 2 else 'asking LLM to retry'}")
            llm_calls[-1]["parse_error"] = str(_parse_exc)
            llm_calls[-1]["raw_output_full_tail"] = raw[-500:]  # last 500 chars for debugging
            if is_last or _parse_errors >= 2:
                verdict = _ui_safe_fallback(kind, heuristics, raw)
                break
            # First parse failure — send a compact correction and retry
            messages.append(AIMessage(content=raw[:3000]))
            messages.append(HumanMessage(
                content="[SYSTEM: Your response could not be parsed as JSON. "
                        "Respond with ONLY valid JSON — no markdown, no explanation, "
                        "no text before or after the JSON object.]"
            ))
            continue

        if parsed.get("action") == "final" or is_last:
            # Programmatic guard: reject the verdict if required tools haven't been called yet.
            # The LLM sometimes returns a verdict on call #1 ignoring mandatory tool guidance.
            if not is_last and _required_tools:
                missing = [tool for tool in _required_tools if not any(
                    k.startswith(tool + "::") or k == tool for k in tool_results
                )]
                if missing:
                    messages.append(AIMessage(content=raw))
                    reasons = "; ".join(_required_tools[t] for t in missing)
                    messages.append(HumanMessage(
                        content=f"[SYSTEM: Verdict rejected — you must call these tools first: {', '.join(missing)}. "
                                f"Reason: {reasons}. Call them now before giving the final verdict.]"
                    ))
                    cb(f"Verdict rejected — missing required tools: {', '.join(missing)}")
                    continue
            verdict = parsed
            break

        if parsed.get("action") == "call_tool":
            tool_name = parsed.get("tool", "")
            messages.append(AIMessage(content=raw))

            # Resolve target path — LLM may specify an inner file via "path"
            import os as _os
            requested_path = parsed.get("path", "").strip()
            path_invalid = False
            if requested_path and requested_path != sample_path:
                # Validate: must be an existing file with no path traversal
                real = _os.path.realpath(requested_path)
                if ".." not in requested_path and _os.path.isfile(real):
                    target_path = real
                else:
                    target_path = sample_path
                    path_invalid = True  # path specified but file not found
            else:
                target_path = sample_path
                requested_path = ""

            # Cache key includes path so tool(inner.rtf) != tool(sample.docx)
            cache_key = f"{tool_name}::{target_path}"
            path_note = f" on {_os.path.basename(target_path)}" if target_path != sample_path else ""

            # Deduplicate: if this exact (tool, path) was already called, return cached
            # result and force the next LLM response to be the final verdict.
            if cache_key in tool_results:
                cb(f"→ tool: {tool_name}{path_note} (cached — forcing verdict next)")
                # Do NOT re-send the full result — the LLM already has it from the prior call.
                # Only send the instruction to conclude; avoids doubling context size.
                result_str = ""
                cached_note = (
                    "[SYSTEM: You already called this tool — result is in your context above. "
                    "Your next response MUST be the final verdict JSON. No more tool calls.]"
                )
                _force_verdict = True
            else:
                cached_note = ""
                if path_invalid:
                    # Path was specified but file not found — return error, do NOT run on sample_path
                    result_str = json.dumps({"error": f"path not found or not allowed: {requested_path}. Check rtfobj_extract output for the correct extracted file paths."})
                    cb(f"→ tool: {tool_name} (invalid path rejected: {requested_path})")
                elif tool_name in tool_registry:
                    cb(f"→ tool: {tool_name}{path_note}")
                    try:
                        result = tool_registry[tool_name](target_path)
                        tool_results[cache_key] = result
                        result_str = json.dumps(result, ensure_ascii=False)[:8000]
                    except Exception as e:
                        result_str = json.dumps({"error": str(e)})
                else:
                    result_str = json.dumps({"error": f"unknown tool '{tool_name}'"})

            remaining = max_tool_calls - iteration - 1
            path_label = f" [on {_os.path.basename(target_path)}]" if target_path != sample_path else ""
            messages.append(HumanMessage(
                content=f"Tool '{tool_name}'{path_label} result:\n{result_str}\n\n"
                        f"({remaining} tool call{'s' if remaining != 1 else ''} remaining)"
                        f"{cached_note}"
            ))
            continue

        # Neither call_tool nor final — treat as final
        verdict = parsed
        break

    if verdict is None:
        verdict = _ui_safe_fallback(kind, heuristics, "no_verdict_produced")

    verdict.setdefault("action", "final")
    verdict.setdefault("file_type", kind)
    verdict.setdefault("risk_level", "unknown")
    verdict.setdefault("confidence", 0)
    verdict.setdefault("top_reasons", [])
    verdict.setdefault("iocs", {
        "urls": [], "domains": [], "ips": [], "emails": [],
        "registry_paths": [], "file_paths": [], "mutexes": [],
        "scheduled_tasks": [], "powershell_commands": [],
    })
    verdict.setdefault("suspicious_strings", [])
    verdict.setdefault("embedded_payloads", [])
    verdict.setdefault("next_steps", [])

    if _thinking_disabled:
        verdict["_thinking_disabled"] = True
        verdict["top_reasons"].insert(0,
            f"Analysis completed using a faster model for performance."
        )

    if strings_score >= 35 and verdict.get("risk_level") == "unknown":
        verdict["risk_level"] = "suspicious"
        verdict["top_reasons"].append(
            f"Enforced: strings_score={strings_score} so risk_level cannot be unknown."
        )

    # If the content filter fired on any tool result, the content itself was flagged as
    # harmful — that is a strong malicious signal. Enforce at least 'suspicious'.
    _RISK_ORDER = ["unknown", "benign", "suspicious", "likely_malware", "malware"]
    if _content_filter_fired:
        current_risk = verdict.get("risk_level", "unknown")
        if _RISK_ORDER.index(current_risk) < _RISK_ORDER.index("suspicious"):
            verdict["risk_level"] = "suspicious"
            verdict.setdefault("top_reasons", []).insert(
                0, "Tool output was blocked by provider content filter — the file contains content "
                   "flagged as dangerous/malicious by the AI safety system."
            )

    return verdict, tool_results, llm_calls
