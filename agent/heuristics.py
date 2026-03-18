from typing import Any, Dict, List

def _clamp_int(x: Any, lo: int = 0, hi: int = 100) -> int:
    try:
        x = int(x)
    except Exception:
        return lo
    return max(lo, min(hi, x))

def _looks_like_real_payload(entry: Any) -> bool:
    """
    Only count extracted artifacts that likely represent embedded payloads.
    Never count PE signature/overlay artifacts.
    """
    if not isinstance(entry, dict):
        return False

    t = str(entry.get("type", "") or "").lower()
    f = str(entry.get("file", "") or "").lower()

    # NEVER count signature/overlay blobs as payloads
    if any(x in t for x in ["pe_overlay", "pe_security_overlay", "overlay", "certificate", "authenticode", "signature", "pkcs7", "x509"]):
        return False

    good_ext = (
        ".exe",".dll",".sys",".elf",".so",
        ".ps1",".js",".vbs",".bat",".cmd",".sh",
        ".jar",".zip",".rar",".7z",
        ".doc",".docm",".xls",".xlsm",".ppt",".pptm",".rtf",".pdf"
    )

    # If type is unknown/generic, require meaningful extension
    if t in ["", "extracted_file", "unknown", "generic"]:
        return f.endswith(good_ext)

    # If type explicitly says it's payload-ish
    if any(x in t for x in ["pe", "elf", "script", "office", "archive", "payload"]):
        return True

    return f.endswith(good_ext)

def heuristic_score_from_evidence(ev: Dict[str, Any], strings_llm: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []

    ent = ev.get("file_entropy")
    if isinstance(ent, (int, float)):
        if ent >= 7.2:
            score += 18; reasons.append(f"High file entropy ({ent}) suggests packing/encryption.")
        elif ent >= 6.8:
            score += 10; reasons.append(f"Moderately high file entropy ({ent}).")

    suspicious = ev.get("suspicious_strings", []) or []
    iocish = sum(1 for it in suspicious if any(str(tag).startswith("ioc:") for tag in (it.get("tags") or [])))
    encoded = sum(1 for it in suspicious if any(str(tag).startswith("encoded:") for tag in (it.get("tags") or [])))

    if iocish >= 2:
        score += 10; reasons.append(f"Deterministic filter: multiple IOC-shaped strings ({iocish}).")
    elif iocish == 1:
        score += 5; reasons.append("Deterministic filter: at least one IOC-shaped string.")

    if encoded >= 2:
        score += 10; reasons.append(f"Deterministic filter: multiple encoded/obfuscated-looking strings ({encoded}).")
    elif encoded == 1:
        score += 5; reasons.append("Deterministic filter: at least one encoded/obfuscated-looking string.")

    extracted = ev.get("extracted_payloads", []) or []
    real_payloads = [x for x in extracted if _looks_like_real_payload(x)]
    if real_payloads:
        score += 8; reasons.append(f"Embedded/extracted payloads present ({len(real_payloads)} likely payload files).")

    # Strings LLM contribution
    llm_score = None
    llm_ok = isinstance(strings_llm, dict) and not strings_llm.get("error")
    if llm_ok:
        sc = strings_llm.get("strings_score", None)
        cf = strings_llm.get("strings_confidence", None)
        rl = strings_llm.get("strings_risk_level", None)
        if (sc in [0, "0", None]) and (cf in [0, "0", None]) and (rl in [None, "", "unknown"]):
            llm_ok = False

    if llm_ok:
        llm_score = _clamp_int(strings_llm.get("strings_score", 0))
        add = int(round(llm_score * 0.45))
        score += add
        reasons.append(f"Strings Analyst LLM score: {llm_score}/100 (adds {add} points).")
        if strings_llm.get("summary"):
            reasons.append(f"Strings Analyst summary: {strings_llm.get('summary')}")
    else:
        reasons.append("Strings Analyst LLM unavailable; relying on deterministic signals only.")

    # Warn if archive extraction failed — entropy/strings are from the container, not the payload
    if ev.get("analysis_note"):
        reasons.insert(0, f"WARNING: {ev['analysis_note']}")

    score = min(100, score)

    hint = "benign"
    if score >= 70: hint = "likely_malware"
    elif score >= 40: hint = "suspicious"
    elif score >= 15: hint = "unknown"

    return {"score": score, "risk_hint": hint, "reasons": reasons[:12], "strings_llm_score": llm_score}
