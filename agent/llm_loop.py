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

    # 2) Fallback: find first {...} block in raw text
    cleaned = _clean_fences(raw)
    m = re.search(r"\{.*?\}", cleaned, flags=re.DOTALL)
    if m:
        try:
            d = _first_dict(json.loads(m.group(0)))
            if d is not None:
                return d
        except Exception:
            pass
    # 3) Last resort: greedy match
    m2 = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not m2:
        raise ValueError("no_json_object_found")
    result = json.loads(m2.group(0))
    d = _first_dict(result)
    if d is not None:
        return d
    raise ValueError("no_json_dict_found")


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
- office/office_openxml: Check olevba for VBA macros, AutoOpen/AutoExec triggers, Shell/WScript calls, base64 blobs, external URL references. If openxml_extract reveals embedded .rtf files, run rtfobj_extract with "path" set to the extracted RTF path. When rtfobj_extract output includes a "[Extracted files saved to disk:]" section, run script_content or js_beautify (for .js/.vbs/.ps1 files) or strings_ascii (for binaries) on EACH listed path — this is mandatory. NEVER call script_content on .rtf, .docx, .doc, .xlsx, .zip, or any binary container file — those are not text scripts and will produce garbage output. Only call script_content on plain text script files (.js, .vbs, .ps1, .hta, .sh, .bat). If it reveals embedded .pdf files, run pdf_analysis on them. If it reveals .exe/.dll, run strings_ascii on them.
- msi: The msi_inventory shows ALL extracted files with type, size, and entropy. Use the "path" field to run targeted tools on suspicious files — e.g. strings_ascii/objdump_pe_headers/pe_section_entropy on high-entropy PEs, authenticode_verify on any signed PE. Analyze ALL PEs, not just the largest — MSI droppers often hide payloads in secondary files.
- pdf: Check for /JavaScript, /OpenAction, /Launch, /EmbeddedFile, suspicious URI streams.
- ps1/vbs/hta/js/shell: Script files — analyse content directly. Obfuscation, encoded payloads, downloads, persistence = malicious.

RULES:
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
        cb(f"LLM call #{iteration + 1} — {payload_bytes:,} bytes in context")
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

            # BadRequestError (4xx) is a client-side error — retrying the identical
            # request will always fail. Break immediately so we fall back to heuristics.
            if "BadRequest" in exc_name or "invalid_argument" in str(last_exc).lower():
                cb(f"LLM call #{iteration + 1} failed with {exc_name} (context too large or invalid request) — skipping retries")
                break

            retry_delay = 5 * (_attempt + 1) if is_timeout else 2 * (_attempt + 1)
            cb(f"LLM call #{iteration + 1} {'timeout' if is_timeout else 'transient error'} "
               f"(attempt {_attempt + 1}/3): {type(last_exc).__name__} — retrying in {retry_delay}s…")
            _time.sleep(retry_delay)

        if last_exc is not None:
            # All retries exhausted — fall back to heuristic-only verdict instead of
            # raising and losing all the preflight/heuristics work done so far.
            cb(f"LLM call #{iteration + 1} failed after all retries — using heuristic fallback")
            _reason = "timeout" if isinstance(last_exc, TimeoutError) else "parse_failed"
            verdict = _ui_safe_fallback(kind, heuristics, f"all_retries_failed: {last_exc}", reason=_reason)
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
        except Exception:
            if is_last:
                verdict = _ui_safe_fallback(kind, heuristics, raw)
            break

        if parsed.get("action") == "final" or is_last:
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

    return verdict, tool_results, llm_calls
