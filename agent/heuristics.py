import datetime
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

    # PE structured metadata signals
    pe_meta = ev.get("pe_meta") or {}
    if pe_meta:
        # Future compilation timestamp
        ts = pe_meta.get("compile_timestamp")
        if isinstance(ts, int) and ts > 0:
            try:
                compile_year = datetime.datetime.utcfromtimestamp(ts).year
                current_year = datetime.datetime.utcnow().year
                years_ahead = compile_year - current_year
                if years_ahead >= 2:
                    score += 25
                    reasons.append(
                        f"PE compile timestamp is {years_ahead} years in the future ({compile_year}): "
                        "strong indicator of timestamp manipulation / masquerading."
                    )
                elif years_ahead == 1:
                    score += 10
                    reasons.append(
                        f"PE compile timestamp is 1 year in the future ({compile_year}): possible timestamp manipulation."
                    )
            except (OSError, OverflowError, ValueError):
                pass

        # Unsigned binary claiming Microsoft authorship
        signed = pe_meta.get("signed")
        version_info = pe_meta.get("version_info") or {}
        company = (version_info.get("CompanyName") or "").lower()
        file_desc = (version_info.get("FileDescription") or "").lower()
        orig_name = (version_info.get("OriginalFilename") or "").lower()
        legal_copy = (version_info.get("LegalCopyright") or "").lower()
        claims_microsoft = any(
            "microsoft" in s for s in [company, file_desc, legal_copy, orig_name]
        )
        if signed is False and claims_microsoft:
            score += 30
            reasons.append(
                "Unsigned PE claims Microsoft authorship in version strings "
                f"(CompanyName='{version_info.get('CompanyName','')}', "
                f"OriginalFilename='{version_info.get('OriginalFilename','')}') "
                "but has no valid Authenticode signature: high-confidence masquerading."
            )
        elif signed is False and ev.get("kind") == "pe":
            # Just being unsigned is a mild signal (many legitimate tools are unsigned)
            pass  # not penalized alone

    # IOC counts from deterministic extraction (domains, IPs, URLs)
    iocs_det = ev.get("iocs_deterministic") or {}
    n_domains = len(iocs_det.get("domains") or [])
    n_ips = len(iocs_det.get("ips") or [])
    n_urls = len(iocs_det.get("urls") or [])
    if n_urls >= 3:
        score += 8; reasons.append(f"Multiple embedded URLs found ({n_urls}).")
    elif n_urls >= 1:
        score += 4; reasons.append(f"Embedded URL(s) found ({n_urls}).")
    if n_ips >= 3:
        score += 8; reasons.append(f"Multiple embedded IP addresses found ({n_ips}).")
    elif n_ips == 1 or n_ips == 2:
        score += 4; reasons.append(f"Embedded IP address(es) found ({n_ips}).")
    if n_domains >= 5:
        score += 6; reasons.append(f"High number of embedded domain strings ({n_domains}).")
    elif n_domains >= 2:
        score += 3; reasons.append(f"Embedded domain strings found ({n_domains}).")

    # .NET capability signals from dnfile analysis
    dotnet = ev.get("dotnet_capabilities") or {}
    if dotnet:
        dn_score = 0
        dn_reasons = []
        if dotnet.get("runtime_code_loading"):
            dn_score += 20; dn_reasons.append("Assembly.Load/runtime code loading")
        if dotnet.get("powershell_execution"):
            dn_score += 25; dn_reasons.append("PowerShell execution capability")
        if dotnet.get("memory_injection"):
            dn_score += 30; dn_reasons.append("memory injection APIs (VirtualAlloc/WriteProcessMemory)")
        if dotnet.get("thread_injection"):
            dn_score += 30; dn_reasons.append("thread injection APIs (CreateRemoteThread/NtCreateThreadEx)")
        if dotnet.get("av_exclusion") or dotnet.get("av_disable"):
            dn_score += 25; dn_reasons.append("AV/Defender exclusion/disable APIs")
        if dotnet.get("embedded_resource_blob"):
            dn_score += 15; dn_reasons.append(f"large embedded .NET resource blob(s): {', '.join(list(dotnet['embedded_resource_blob'])[:2])}")
        if dotnet.get("obfuscation"):
            dn_score += 10; dn_reasons.append("obfuscated type/method names")
        if dotnet.get("process_creation") and dotnet.get("runtime_code_loading"):
            dn_score += 10; dn_reasons.append("process creation + runtime loading combo")
        if dn_score > 0:
            score += min(dn_score, 50)
            reasons.append(f".NET analysis: {'; '.join(dn_reasons)}.")

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
