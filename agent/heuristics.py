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

    upx_packed = ev.get("upx_packed", False)
    # If UPX unpack succeeded the binary was modified in-place — entropy/strings are from the
    # unpacked binary and should be scored normally. If unpack failed, entropy reflects the
    # compressed UPX sections and is an expected artifact, not a malware indicator.
    upx_entropy_artifact = upx_packed and not ev.get("upx_unpack_ok", False)

    ent = ev.get("file_entropy")
    if isinstance(ent, (int, float)):
        if upx_entropy_artifact:
            reasons.append(
                f"File entropy ({ent}) reflects UPX compressed sections (upx_unpack failed) "
                "— expected artifact of UPX packing, not malicious encryption."
            )
        elif ent >= 7.2:
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
        has_repro = pe_meta.get("has_repro_debug", False)

        # Future compilation timestamp
        # If IMAGE_DEBUG_TYPE_REPRO (0x10) is present the TimeDateStamp is a 32-bit
        # content hash — NOT a real date. Microsoft builds all modern Windows system
        # binaries this way (/Brepro flag). Penalising this causes false positives on
        # legitimate Windows binaries like conhost.exe (timestamp year 2096).
        # Only penalise when the repro debug entry is absent (real timestamp tampering).
        ts = pe_meta.get("compile_timestamp")
        if isinstance(ts, int) and ts > 0 and not has_repro:
            try:
                compile_year = datetime.datetime.utcfromtimestamp(ts).year
                current_year = datetime.datetime.utcnow().year
                years_ahead = compile_year - current_year
                if years_ahead >= 2:
                    score += 25
                    reasons.append(
                        f"PE compile timestamp is {years_ahead} years in the future ({compile_year}) "
                        "with no /Brepro debug entry: strong indicator of timestamp manipulation."
                    )
                elif years_ahead == 1:
                    score += 10
                    reasons.append(
                        f"PE compile timestamp is 1 year in the future ({compile_year}) "
                        "with no /Brepro debug entry: possible timestamp manipulation."
                    )
            except (OSError, OverflowError, ValueError):
                pass
        elif isinstance(ts, int) and ts > 0 and has_repro:
            # Timestamp is a content hash (reproducible build) — not suspicious.
            # Note for LLM context only, no score change.
            try:
                compile_year = datetime.datetime.utcfromtimestamp(ts).year
                current_year = datetime.datetime.utcnow().year
                if compile_year > current_year:
                    reasons.append(
                        f"PE compile timestamp appears to be year {compile_year} but "
                        "IMAGE_DEBUG_TYPE_REPRO is present: timestamp is a content hash "
                        "(Microsoft /Brepro reproducible build), not a real date — not suspicious."
                    )
            except (OSError, OverflowError, ValueError):
                pass

        # Unsigned binary claiming Microsoft authorship
        # Legitimate Windows system files are catalog-signed (not embedded Authenticode).
        # osslsigncode reports "not signed" for these — that is expected and not a red flag
        # when IMAGE_DEBUG_TYPE_REPRO is also present (consistent MS build pipeline).
        # Only flag when repro debug is absent: that combination is highly anomalous.
        signed = pe_meta.get("signed")
        version_info = pe_meta.get("version_info") or {}
        company = (version_info.get("CompanyName") or "").lower()
        file_desc = (version_info.get("FileDescription") or "").lower()
        orig_name = (version_info.get("OriginalFilename") or "").lower()
        legal_copy = (version_info.get("LegalCopyright") or "").lower()
        claims_microsoft = any(
            "microsoft" in s for s in [company, file_desc, legal_copy, orig_name]
        )
        if signed is False and claims_microsoft and not has_repro:
            score += 30
            reasons.append(
                "Unsigned PE claims Microsoft authorship in version strings "
                f"(CompanyName='{version_info.get('CompanyName','')}', "
                f"OriginalFilename='{version_info.get('OriginalFilename','')}') "
                "with no /Brepro debug entry: high-confidence masquerading."
            )
        elif signed is False and claims_microsoft and has_repro:
            # Catalog-signed Windows system binary — normal, no penalty.
            reasons.append(
                f"PE claims Microsoft authorship ('{version_info.get('CompanyName','')}') "
                "and has no embedded Authenticode signature, but IMAGE_DEBUG_TYPE_REPRO "
                "is present: consistent with a catalog-signed Windows system binary."
            )
        elif signed is None and claims_microsoft:
            # Signature is present and digest intact, but the Linux CA store is missing
            # the issuer root certificate (common for Microsoft root CAs).
            # This is NOT unsigned — treat as signed for scoring purposes.
            reasons.append(
                f"PE claims Microsoft authorship ('{version_info.get('CompanyName','')}') "
                "and has an embedded Authenticode signature with matching digest, but the "
                "certificate chain could not be verified locally (Linux CA store missing "
                "Microsoft root CA). This is expected for legitimate Microsoft software "
                "analyzed on Linux — not a red flag."
            )

        # Signer certificate analysis — self-signed, unknown CA, company mismatch
        _WELL_KNOWN = {
            "microsoft", "google", "adobe", "apple", "mozilla",
            "oracle", "amazon", "intel", "nvidia", "cisco",
        }
        signer_info = pe_meta.get("signer_info") or {}
        if signer_info:
            signer_org = (signer_info.get("signer_org") or "").lower()
            signer_cn  = (signer_info.get("signer_cn")  or "").lower()
            is_self_signed = signer_info.get("is_self_signed", False)

            cert_claims_known  = any(k in signer_org or k in signer_cn  for k in _WELL_KNOWN)
            vi_claims_known    = claims_microsoft or any(
                k in company or k in file_desc or k in legal_copy or k in orig_name
                for k in _WELL_KNOWN
            )

            if is_self_signed:
                score += 15
                reasons.append(
                    f"PE has a self-signed Authenticode certificate "
                    f"(signer: '{signer_info.get('signer_org') or signer_info.get('signer_cn', 'unknown')}') "
                    "— not issued by any trusted CA."
                )
                if cert_claims_known:
                    # Self-signed cert that itself claims to be a well-known company
                    score += 20
                    reasons.append(
                        f"Self-signed certificate claims to be from a well-known company "
                        f"('{signer_info.get('signer_org','')}') — high-confidence impersonation."
                    )
                elif vi_claims_known:
                    # version_info claims well-known company but cert is self-signed unknown
                    score += 15
                    reasons.append(
                        f"Version info claims '{version_info.get('CompanyName','')}' "
                        f"but the Authenticode certificate is self-signed by an unknown entity "
                        f"('{signer_info.get('signer_org') or signer_info.get('signer_cn', '')}')."
                    )

            elif signed is True:
                # Chain verified — check for company mismatch between version_info and cert
                vi_company   = (version_info.get("CompanyName") or "").strip()
                cert_company = (signer_info.get("signer_org") or "").strip()
                if vi_company and cert_company:
                    def _norm(s: str) -> str:
                        for sfx in [" corporation", " corp", " inc", " ltd", " llc", " co.", " gmbh", " s.a."]:
                            s = s.lower().replace(sfx, "")
                        return s.strip()
                    if vi_claims_known and not cert_claims_known:
                        score += 20
                        reasons.append(
                            f"Version info claims '{vi_company}' but Authenticode is signed by "
                            f"'{cert_company}': well-known company claimed in metadata but "
                            "signed by a different entity."
                        )
                    elif _norm(vi_company) not in _norm(cert_company) and _norm(cert_company) not in _norm(vi_company):
                        score += 10
                        reasons.append(
                            f"Version info company ('{vi_company}') differs from "
                            f"Authenticode signer ('{cert_company}')."
                        )

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
