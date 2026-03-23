import json
import re
from collections import Counter
from typing import Any, Dict

import config
from agent.llm_factory import get_llm


def _filter_strings_preview(text: str) -> str:
    """
    Two-pass filter to remove LLM-hostile noise from strings output before
    sending to the LLM.

    Pass 1 — repetitive-char collapse:
      Lines where ≥70% of characters are the same single character AND the line
      is longer than 18 chars are replaced with [rep: 'X'×N].
      These come from packed/encrypted PE sections leaking through `strings` or
      FLOSS. They add no analytical value but can trigger LLM safety-filter
      scanning that stalls the request indefinitely.

    Pass 2 — low word-density drop:
      Lines where fewer than 25% of characters are word characters (a-z A-Z 0-9 _)
      AND the line is longer than 12 chars are dropped entirely.
      These are FLOSS decoding artifacts or binary noise — dense punctuation
      sequences with no readable tokens (e.g. OjEm`?tX{,Zub=aY7&:ICG...).
      Real strings with IOC value (paths, URLs, API names) always contain
      enough word characters to survive this filter.
    """
    out = []
    for line in text.splitlines():
        s = line.strip()

        if len(s) >= 18:
            top_char, top_count = Counter(s).most_common(1)[0]
            if top_count / len(s) >= 0.70:
                out.append(f"[rep: {repr(top_char)}×{len(s)}]")
                continue

        if len(s) >= 12:
            word_chars = sum(1 for c in s if c.isalnum() or c == '_')
            if word_chars / len(s) < 0.40:
                continue  # drop — too dense with punctuation to be useful

        # Pass 3 — consecutive-run drop:
        #   Any line with a run of ≥6 identical non-space characters is binary noise
        #   (e.g. QQQQQQQ...WWWWWW or mixed garbage from packed sections that
        #   slip through the single-char rep filter above).
        if len(s) >= 10:
            import re as _re
            if _re.search(r'([^\s])\1{5,}', s):
                continue

        # Pass 4 — symbol-diversity drop:
        #   For lines ≥30 chars, count distinct non-alphanumeric, non-underscore,
        #   non-space characters. Real strings (URLs, paths, API names) use a small
        #   symbol set (\\ : . / - = @ at most). Random binary noise extracted by
        #   `strings` from packed sections uses many diverse symbols drawn from the
        #   full printable-ASCII range. Threshold >8 distinct symbols safely removes
        #   that garbage without touching legitimate IOCs or API names.
        if len(s) >= 30:
            distinct_syms = len({c for c in s if not (c.isalnum() or c in ('_', ' '))})
            if distinct_syms > 8:
                continue

        out.append(line)
    return "\n".join(out)


def _clean_fences(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.IGNORECASE)
        s = re.sub(r"\s*```$", "", s)
    return s.strip()

def _unwrap_text(payload: Any) -> str | None:
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

    # 1) wrapper JSON
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

    # 2) fallback: find first {...} block
    cleaned = _clean_fences(raw)
    m = re.search(r"\{.*?\}", cleaned, flags=re.DOTALL)
    if m:
        try:
            d = _first_dict(json.loads(m.group(0)))
            if d is not None:
                return d
        except Exception:
            pass
    # 3) last resort: greedy match
    m2 = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not m2:
        raise ValueError("no_json_object_found")
    result = json.loads(m2.group(0))
    d = _first_dict(result)
    if d is not None:
        return d
    raise ValueError("no_json_dict_found")


def clamp(x: Any) -> int:
    try:
        x = int(x)
    except Exception:
        return 0
    return max(0, min(100, x))


def analyze_strings_llm(
    model: str,
    kind: str,
    file_entropy: float | None,
    strings_preview: str,
    max_chars: int = 20000,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    LLM-only analysis of a short strings preview.
    Must return a compact JSON with:
      strings_risk_level, strings_score, strings_confidence, summary, evidence[], iocs{}
    """
    raw_preview = (strings_preview or "")[:max_chars]
    sp = _filter_strings_preview(raw_preview)

    prompt = f"""
You are a malware strings analyst. You see ONLY a strings preview (not full file).
Decide if the strings suggest benign, suspicious, or likely_malware.

Return RAW JSON ONLY — no markdown, no code fences, no explanation before or after:
{{
  "strings_risk_level":"benign|suspicious|likely_malware|unknown",
  "strings_score":0-100,
  "strings_confidence":0-100,
  "summary":"one short paragraph",
  "evidence":[{{"line":"...","why":"...","tags":["attack_tooling|c2|persistence|crypto|obfuscation|ioc"]}}],
  "iocs":{{"urls":[],"domains":[],"ips":[],"emails":[],"registry_paths":[],"file_paths":[],"mutexes":[],"scheduled_tasks":[],"powershell_commands":[]}}
}}

Context:
- file_type={kind}
- entropy={file_entropy}

Strings preview:
{sp}
""".strip()

    cb = progress_cb or (lambda msg: None)
    payload_bytes = len(prompt.encode("utf-8"))
    raw_bytes = len(raw_preview.encode("utf-8"))
    filtered_bytes = len(sp.encode("utf-8"))
    reduction = raw_bytes - filtered_bytes
    reduction_note = f" (strings filtered: {raw_bytes:,}→{filtered_bytes:,} bytes, -{reduction:,} repetitive noise)" if reduction > 0 else ""
    cb(f"Strings LLM — {payload_bytes:,} bytes sent{reduction_note}")
    import time as _time
    import threading as _threading

    last_exc = None
    for _attempt in range(3):
        # Fresh client on every attempt — ensures a new HTTP connection rather
        # than reusing a stalled socket from a previous timed-out request.
        try:
            llm = get_llm(model)
        except Exception as _e:
            return {"error": f"strings_llm_init_error: {type(_e).__name__}: {_e}",
                    "strings_score": 0, "strings_risk_level": "unknown",
                    "strings_confidence": 0, "summary": "", "evidence": [], "iocs": {},
                    "_prompt_head": prompt[:30000],
                    "_raw_output": f"LLM client init failed: {_e}"}

        _t0 = _time.time()

        # Background thread sends "still working" pings every 10 s
        _done = _threading.Event()
        def _ping(_t0=_t0):
            while not _done.wait(10):
                cb(f"Strings LLM still working… ({_time.time() - _t0:.0f}s)")
        _pt = _threading.Thread(target=_ping, daemon=True)
        _pt.start()

        # Application-level timeout: provider-level timeouts only guard connection
        # setup, not streaming reads — a stalled response hangs indefinitely.
        # Run invoke in a daemon thread; abandon and retry with a fresh client if it stalls.
        _result: list = [None]
        _err: list = [None]
        def _do(_result=_result, _err=_err, _llm=llm):
            try:
                _result[0] = _llm.invoke(prompt)
            except Exception as _e:
                _err[0] = _e
        _worker = _threading.Thread(target=_do, daemon=True)
        _worker.start()
        _worker.join(timeout=config.LLM_TIMEOUT)

        _done.set()
        _elapsed = _time.time() - _t0

        if _worker.is_alive():
            # Still running after timeout — server stalled; abandon and retry
            last_exc = TimeoutError(
                f"LLM call timed out after {config.LLM_TIMEOUT}s "
                f"(input {payload_bytes:,} bytes — likely server-side stall, not input size)"
            )
        elif _err[0]:
            last_exc = _err[0]
        else:
            msg = _result[0]
            last_exc = None

        if last_exc is None:
            cb(f"Strings LLM completed in {_elapsed:.1f}s")
            break

        is_timeout = isinstance(last_exc, TimeoutError)
        retry_delay = 15 * (_attempt + 1) if is_timeout else 2 * (_attempt + 1)
        cb(f"Strings LLM {'timeout' if is_timeout else 'transient error'} "
           f"(attempt {_attempt + 1}/3): {type(last_exc).__name__} — "
           f"retrying in {retry_delay}s…")
        _time.sleep(retry_delay)

    if last_exc is not None:
        return {"error": f"strings_llm_network_error: {last_exc}", "strings_score": 0,
                "strings_risk_level": "unknown", "strings_confidence": 0, "summary": "", "evidence": [], "iocs": {},
                "_prompt_head": prompt[:30000],
                "_raw_output": f"No response — all retries failed: {last_exc}"}
    raw = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)

    try:
        obj = _parse_any_json_object(raw)
        # normalize fields
        obj["strings_score"] = clamp(obj.get("strings_score", 0))
        obj["strings_confidence"] = clamp(obj.get("strings_confidence", 0))
        obj.setdefault("strings_risk_level", "unknown")
        obj.setdefault("summary", "")
        obj.setdefault("evidence", [])
        obj.setdefault("iocs", {
            "urls": [], "domains": [], "ips": [], "emails": [],
            "registry_paths": [], "file_paths": [], "mutexes": [],
            "scheduled_tasks": [], "powershell_commands": []
        })
        obj["_raw_output"] = raw[:20000]
        obj["_prompt_head"] = prompt[:30000]
        return obj
    except Exception as e:
        return {"error": f"strings_llm_parse_failed: {type(e).__name__}", "raw": raw[:20000], "prompt_head": prompt[:30000]}
