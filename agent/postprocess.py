from typing import Any, Dict, List

def _safe_list(x, limit=200):
    if not isinstance(x, list):
        return []
    return x[:limit]

def _nonempty_list(x):
    return isinstance(x, list) and len(x) > 0

def _clean_file_paths(paths: List[str]) -> List[str]:
    out = []
    for p in paths or []:
        if not isinstance(p, str):
            continue
        s = p.strip()
        if len(s) < 5:
            continue
        if s.startswith("/") and s.count("/") < 2:
            continue
        out.append(s)
    ded, seen = [], set()
    for x in out:
        if x not in seen:
            seen.add(x)
            ded.append(x)
    return ded[:200]

def _authenticode_verified(preflight: Dict[str, Any]) -> bool:
    av = (preflight or {}).get("authenticode_verify") or {}
    if isinstance(av, dict):
        rc = av.get("rc", None)
        if rc == 0:
            return True
        txt = ((av.get("stdout") or "") + "\n" + (av.get("stderr") or "")).lower()
        if "verified" in txt and "fail" not in txt:
            return True
    return False

def _only_benign_overlay(payloads: List[Dict[str, Any]]) -> bool:
    """
    True if payload list is empty OR contains only overlay/signature/cert artifacts.
    """
    if not payloads:
        return True
    for p in payloads:
        if not isinstance(p, dict):
            return False
        t = str(p.get("type", "") or "").lower()
        f = str(p.get("file", "") or "").lower()
        if any(x in t for x in ["pe_security_overlay", "pe_overlay", "overlay", "certificate", "authenticode", "signature"]):
            continue
        # if unknown, treat .bin as not benign
        if t in ["", "extracted_file"] and f.endswith(".bin"):
            return False
        return False
    return True

def enforce_verdict(
    verdict: Dict[str, Any],
    evidence_pack: Dict[str, Any],
    heuristics: Dict[str, Any],
    preflight: Dict[str, Any],
    strings_llm: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    strings_llm = strings_llm or {}

    # If verdict is an error fallback, keep it but ensure keys exist
    verdict.setdefault("action", "final")
    verdict.setdefault("file_type", preflight.get("kind", verdict.get("file_type", "unknown")))
    verdict.setdefault("risk_level", "unknown")
    verdict.setdefault("confidence", 0)
    verdict.setdefault("top_reasons", [])
    verdict.setdefault("iocs", {"urls": [], "domains": [], "ips": [], "emails": [], "registry_paths": [], "file_paths": [],
                               "mutexes": [], "scheduled_tasks": [], "powershell_commands": []})
    verdict.setdefault("suspicious_strings", [])
    verdict.setdefault("embedded_payloads", [])
    verdict.setdefault("next_steps", [])

    # --- merge IOCs from deterministic + strings_llm into verdict.iocs ---
    iocs_det = evidence_pack.get("iocs_deterministic", {}) or {}
    iocs_str = (strings_llm.get("iocs") or {}) if isinstance(strings_llm, dict) else {}
    iocs = verdict.get("iocs") if isinstance(verdict.get("iocs"), dict) else {}

    keys = ["urls","domains","ips","emails","registry_paths","file_paths","mutexes","scheduled_tasks","powershell_commands"]
    for k in keys:
        iocs.setdefault(k, [])

    def merge_lists(a, b, c):
        out = []
        for src in [a, b, c]:
            for x in _safe_list(src, 200):
                if x not in out:
                    out.append(x)
        return out[:200]

    for k in keys:
        iocs[k] = merge_lists(iocs.get(k, []), iocs_str.get(k, []), iocs_det.get(k, []))

    iocs["file_paths"] = _clean_file_paths(iocs.get("file_paths", []))
    verdict["iocs"] = iocs

    # suspicious strings
    if not _nonempty_list(verdict.get("suspicious_strings", [])):
        ss = []
        ev_lines = strings_llm.get("evidence")
        if isinstance(ev_lines, list) and ev_lines:
            for e in ev_lines[:20]:
                if isinstance(e, dict) and e.get("line"):
                    ss.append({"line": e.get("line"), "why": e.get("why", ""), "tags": e.get("tags", [])})
        if not ss:
            ss = evidence_pack.get("suspicious_strings", [])[:40]
        verdict["suspicious_strings"] = ss

    # embedded payloads default
    if not _nonempty_list(verdict.get("embedded_payloads", [])):
        verdict["embedded_payloads"] = (preflight.get("extraction") or {}).get("extracted", [])[:200]

    # --- BENIGN GUARD: don't let heuristics override a verified-signed PE with no real IOCs/payloads ---
    kind = preflight.get("kind", verdict.get("file_type", "unknown"))
    verified = (kind == "pe") and _authenticode_verified(preflight)

    # "real IOCs" exclude file_paths; only network/identity artifacts
    has_real_ioc = any(len(iocs.get(k, [])) > 0 for k in ["urls","domains","ips","emails"])
    only_benign_overlay = _only_benign_overlay(verdict.get("embedded_payloads", []))

    if verified and (not has_real_ioc) and only_benign_overlay:
        # If LLM said benign, keep it benign no matter what heuristics say
        if verdict.get("risk_level") in ["benign", "unknown", "suspicious", "likely_malware"]:
            verdict["risk_level"] = "benign"
            # optionally cap confidence to avoid scary 100% (feel free to remove this)
            try:
                verdict["confidence"] = min(int(verdict.get("confidence", 0) or 0), 95)
            except Exception:
                verdict["confidence"] = 95

    # --- Escalate risk_level based on strong evidence when LLM undershot ---
    strings_score = int((strings_llm.get("strings_score") or 0) if isinstance(strings_llm, dict) else 0)
    heuristic_score = int((heuristics.get("score") or 0) if isinstance(heuristics, dict) else 0)

    # Upgrade suspicious/unknown → likely_malware when evidence is overwhelming
    if not verified and verdict.get("risk_level") in ("unknown", "suspicious"):
        if strings_score >= 75 or heuristic_score >= 70:
            verdict["risk_level"] = "likely_malware"
            verdict.setdefault("top_reasons", []).insert(0,
                f"Escalated to likely_malware: strings_score={strings_score}, heuristic_score={heuristic_score}."
            )

    # Fill in confidence=0 with a heuristic-derived estimate
    try:
        current_conf = int(verdict.get("confidence") or 0)
    except Exception:
        current_conf = 0
    if current_conf == 0:
        evidence_conf = min(95, max(strings_score, heuristic_score))
        verdict["confidence"] = evidence_conf

    # --- Top reasons: append heuristics & strings summary (without changing risk unless needed) ---
    reasons: List[str] = verdict.get("top_reasons") if isinstance(verdict.get("top_reasons"), list) else []

    # Attach heuristics summary for transparency
    hr = heuristics.get("reasons")
    if isinstance(hr, list) and hr:
        reasons.append("Heuristics: - " + " - ".join([str(x) for x in hr[:6]]))

    # Attach strings LLM status
    if isinstance(strings_llm, dict) and strings_llm.get("error"):
        reasons.append("Strings Analyst LLM unavailable; relying on deterministic signals only.")

    # de-dup
    dedup, seen = [], set()
    for r in reasons:
        key = str(r).strip()
        if key and key not in seen:
            seen.add(key)
            dedup.append(r)
    verdict["top_reasons"] = dedup[:14]

    return verdict
