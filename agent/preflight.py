from pathlib import Path
from typing import Any, Dict

from tools.cli_tools import (
    network_artifacts_scan, phishing_analysis_scan, email_parse, detect_installer, installer_extract,
    guess_kind_from_fileinfo,
    file_info, sha256, entropy_shannon, strings_ascii, strings_preview_text, extract_payloads, code_links,
    radare2_quick_json, radare2_entry_disasm,
    objdump_pe_headers, objdump_pe_imports_dynamic, ghidra_malhaus,
    readelf_all, objdump_elf_dynamic, ldd_deps,
    authenticode_verify,
    oledump_list, olevba_json, oleobj_extract, rtfobj_extract, openxml_list, openxml_extract, oledump_details,
    upx_detect, upx_unpack,
    msi_extract,
    floss_strings,
    pdf_analysis, lnk_analysis,
    _archive_extract_impl,
    pe_section_entropy,
    dotnet_analysis,
    binwalk_scan,
    pe_meta_structured,
    jar_manifest, jarsigner_verify, jar_class_list, javap_disasm, jar_extract_inner,
)

# Optional custom tools (won't break if not installed/enabled)
try:
    from custom_tools.ghidra_headless import ghidra_headless_summary  # type: ignore
except Exception:
    ghidra_headless_summary = None  # type: ignore


def _ghidra_on_extracted_pes(
    file_paths: list,
    options: Dict[str, Any],
    cb,
    label: str = "",
    cap: int = 3,
) -> Dict[str, Any]:
    """
    Run ghidra_malhaus on any PE (MZ magic) files in file_paths.
    Only runs when options["use_ghidra"] is set. Caps at `cap` files.
    Returns {basename: ghidra_result}.
    """
    if not options.get("use_ghidra"):
        return {}
    results: Dict[str, Any] = {}
    seen = 0
    prefix = f"[{label}] " if label else ""
    for fpath in file_paths:
        if seen >= cap:
            break
        p = Path(fpath)
        if not p.is_file():
            continue
        try:
            with open(p, "rb") as _f:
                if _f.read(2) != b"MZ":
                    continue
        except Exception:
            continue
        cb(f"{prefix}Ghidra: scanning extracted PE {p.name} (this takes a while…)")
        results[p.name] = ghidra_malhaus(str(p))
        seen += 1
    return results


def preflight(sample: str, options: Dict[str, Any] | None = None, progress_cb=None) -> Dict[str, Any]:
    options = options or {}
    cb = progress_cb or (lambda msg: None)

    cb("Detecting file type")
    fi = file_info(sample)
    kind = guess_kind_from_fileinfo(fi.get("stdout", ""), sample)

    cb("Computing SHA-256")
    h = sha256(sample)

    pre: Dict[str, Any] = {
        "file_info": fi,
        "kind": kind,
        "sha256": h,
    }

    # --- UPX: unpack in-place BEFORE entropy/strings so analysis is on real content ---
    # Also covers UPX-packed ELFs: after unpack, re-detect the true kind.
    if kind in ("pe", "elf"):
        cb("Checking for UPX packing")
        if upx_detect(sample):
            pre["upx_packed"] = True
            cb("Unpacking UPX")
            pre["upx_unpack"] = upx_unpack(sample)
            if (pre["upx_unpack"] or {}).get("ok"):
                cb("Re-detecting file type after UPX unpack")
                fi_post = file_info(sample)
                kind_post = guess_kind_from_fileinfo(fi_post.get("stdout", ""), sample)
                if kind_post not in ("unknown", ""):
                    kind = kind_post
                    pre["kind"] = kind
        else:
            pre["upx_packed"] = False

    cb("Computing entropy")
    ent = entropy_shannon(sample)

    # strings_preview feeds strings_llm (the LLM pre-analysis pass on strings).
    # Always use plain strings_ascii: it extracts existing printable ASCII sequences
    # and produces clean, predictable output for LLM IOC analysis.
    # FLOSS (deobfuscated stack strings) is run separately and stored in
    # pre["floss_result"] so the verdict LLM can access it via mandatory_snips —
    # its decoding artifacts do not pollute the strings_llm prompt.
    if kind in ("pe", "elf"):
        cb("FLOSS: deobfuscating strings")
        floss_result = floss_strings(sample)
        if (floss_result.get("stdout") or "").strip():
            pre["floss_result"] = floss_result
    cb("Extracting strings")
    preview = strings_preview_text(sample)

    cb("Extracting embedded payloads")
    extraction = extract_payloads(sample)

    pre["entropy"] = ent
    pre["strings_preview"] = preview
    pre["extraction"] = extraction

    # --- Office / OpenXML ---
    if kind == "office":
        cb("oledump: listing streams")
        pre["mandatory_oledump_list"] = oledump_list(sample)
        cb("olevba: extracting VBA")
        pre["mandatory_olevba_json"] = olevba_json(sample)
        cb("oleobj: extracting objects")
        pre["mandatory_oleobj_extract"] = oleobj_extract(sample)
        pre["mandatory_rtfobj_extract"] = rtfobj_extract(sample)
        pre["mandatory_oledump_details"] = oledump_details(sample)
        _office_pe_paths = (
            list(pre["mandatory_oleobj_extract"].get("extracted_files") or []) +
            list(pre["mandatory_rtfobj_extract"].get("extracted_files") or [])
        )
        _ghidra_office = _ghidra_on_extracted_pes(_office_pe_paths, options, cb)
        if _ghidra_office:
            pre["mandatory_ghidra_extracted_pes"] = _ghidra_office

    if kind == "office_openxml":
        cb("Listing OpenXML contents")
        pre["mandatory_openxml_list"] = openxml_list(sample)
        cb("Extracting OpenXML contents")
        pre["mandatory_openxml_extract"] = openxml_extract(sample)
        _openxml_pe_paths = list(pre["mandatory_openxml_extract"].get("extracted_files") or [])
        _ghidra_openxml = _ghidra_on_extracted_pes(_openxml_pe_paths, options, cb)
        if _ghidra_openxml:
            pre["mandatory_ghidra_extracted_pes"] = _ghidra_openxml

    if kind == "pe":
        cb("Authenticode verification")
        pre["authenticode_verify"] = authenticode_verify(sample)
        cb("objdump: PE headers/sections")
        pre["mandatory_objdump_pe_headers"] = objdump_pe_headers(sample)
        cb("objdump: PE imports")
        pre["mandatory_objdump_pe_dynamic"] = objdump_pe_imports_dynamic(sample)
        cb("radare2: analysis")
        pre["mandatory_radare2_info"] = radare2_quick_json(sample)
        cb("radare2: entry disasm")
        pre["mandatory_radare2_entry"] = radare2_entry_disasm(sample)
        cb("PE section entropy")
        pre["mandatory_pe_section_entropy"] = pe_section_entropy(sample)

        cb(".NET metadata analysis")
        pre["mandatory_dotnet_analysis"] = dotnet_analysis(sample)
        cb("binwalk: embedded signature scan")
        pre["mandatory_binwalk"] = binwalk_scan(sample)
        cb("PE: structured metadata (timestamp, version info)")
        pre["mandatory_pe_meta"] = pe_meta_structured(sample)

        if options.get("use_ghidra"):
            cb("Ghidra: full scan (this takes a while…)")
            pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(sample)

    if kind == "elf":
        cb("readelf: full headers")
        pre["mandatory_readelf_all"] = readelf_all(sample)
        cb("objdump: ELF dynamic section")
        pre["mandatory_objdump_elf_dynamic"] = objdump_elf_dynamic(sample)
        cb("readelf: shared library deps")
        pre["mandatory_ldd_deps"] = ldd_deps(sample)
        cb("binwalk: embedded signature scan")
        pre["mandatory_binwalk"] = binwalk_scan(sample)
        if options.get("use_ghidra"):
            cb("Ghidra: full scan (this takes a while…)")
            pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(sample)

    if kind == "msi":
        cb("7z: extracting MSI contents")
        msi = msi_extract(sample)
        pre["mandatory_msi_extract"] = msi
        if msi.get("pe_strings_preview"):
            pre["strings_preview"] = msi["pe_strings_preview"][:12000]
        # Run mandatory PE analysis on ALL extracted PE/ELF files (cap at 5)
        _msi_pes = [f["path"] for f in (msi.get("pe_files") or []) if f.get("path")][:5]
        if not _msi_pes and msi.get("largest_pe"):
            _msi_pes = [msi["largest_pe"]]
        pre["mandatory_msi_pe_analysis"] = {}
        for _pe_path in _msi_pes:
            _pe_name = Path(_pe_path).name
            cb(f"MSI: authenticode/headers/entropy on {_pe_name}")
            _pe_entry = {
                "path": _pe_path,
                "authenticode": authenticode_verify(_pe_path),
                "pe_headers":   objdump_pe_headers(_pe_path),
                "pe_entropy":   pe_section_entropy(_pe_path),
            }
            cb(f"MSI: .NET analysis on {_pe_name}")
            _dotnet = dotnet_analysis(_pe_path)
            if not (_dotnet.get("error", "").startswith("Not a .NET PE") or
                    _dotnet.get("error", "").startswith("dnfile")):
                _pe_entry["dotnet_analysis"] = _dotnet
            if options.get("use_ghidra"):
                cb(f"MSI: Ghidra full scan on {_pe_name} (this takes a while…)")
                _pe_entry["ghidra_malhaus"] = ghidra_malhaus(_pe_path)
            pre["mandatory_msi_pe_analysis"][_pe_name] = _pe_entry

    if kind == "pdf":
        cb("PDF: keyword analysis")
        pre["mandatory_pdf_analysis"] = pdf_analysis(sample)

    if kind == "lnk":
        cb("LNK: parsing shortcut")
        pre["mandatory_lnk_analysis"] = lnk_analysis(sample)

    if kind == "jar":
        cb("JAR: reading MANIFEST.MF")
        pre["mandatory_jar_manifest"] = jar_manifest(sample)
        cb("JAR: listing class files and resources")
        pre["mandatory_jar_class_list"] = jar_class_list(sample)
        cb("JAR: verifying signature (jarsigner)")
        pre["mandatory_jarsigner_verify"] = jarsigner_verify(sample)
        cb("JAR: extracting and inventorying inner files")
        pre["mandatory_jar_extract"] = jar_extract_inner(sample)
        cb("JAR: disassembling classes (javap)")
        pre["mandatory_javap_disasm"] = javap_disasm(sample)

    if kind in ("vbs", "hta"):
        cb("Reading script content")
        try:
            pre["mandatory_script_content"] = Path(sample).read_text(errors="replace")[:20000]
        except Exception as e:
            pre["mandatory_script_content"] = f"read error: {e}"

    if kind == "archive":
        cb("Extracting archive contents")
        password = (options or {}).get("archive_password", "")
        arc = _archive_extract_impl(sample, password=password)
        pre["mandatory_archive_extract"] = arc

        if not arc.get("ok") and arc.get("wrong_password"):
            cb("Archive extraction failed — wrong or missing password")
            pre["archive_wrong_password"] = True
            pre["analysis_abort"] = True
            pre["analysis_abort_reason"] = "wrong_password"
            return pre

        inner = arc.get("promoted_file") or arc.get("largest_pe")
        inner_kind = arc.get("promoted_kind")

        if inner and inner_kind and Path(inner).is_file():
            inner_name = Path(inner).name
            depth = arc.get("nesting_depth", 0)
            depth_note = f" (nested {depth} level{'s' if depth != 1 else ''} deep)" if depth > 0 else ""
            cb(f"{inner_kind.upper()} found inside archive{depth_note}: {inner_name} — promoting to full {inner_kind} analysis")
            pre["effective_sample"] = inner
            # sha256sum-style second line: the file actually analysed. The first token stays the uploaded
            # container's hash (report key, cache key, API "sha256") for every existing reader.
            _ph = sha256(inner)
            if (_ph.get("stdout") or "").strip() and isinstance(pre.get("sha256"), dict):
                pre["sha256"]["stdout"] = (pre["sha256"].get("stdout") or "").rstrip("\n") + "\n" + _ph["stdout"].strip() + "\n"
            pre["container_kind"] = "archive"

            # UPX check for PE/ELF before anything else
            if inner_kind in ("pe", "elf"):
                cb(f"[{inner_name}] Checking for UPX packing")
                if upx_detect(inner):
                    pre["upx_packed"] = True
                    cb(f"[{inner_name}] Unpacking UPX")
                    pre["upx_unpack"] = upx_unpack(inner)
                    if (pre["upx_unpack"] or {}).get("ok"):
                        cb(f"[{inner_name}] Re-detecting file type after UPX unpack")
                        fi_post = file_info(inner)
                        kind_post = guess_kind_from_fileinfo(fi_post.get("stdout", ""), inner)
                        if kind_post not in ("unknown", ""):
                            inner_kind = kind_post
                else:
                    pre["upx_packed"] = False

            kind = inner_kind
            pre["kind"] = kind

            # Recompute entropy and strings on the promoted file
            cb(f"[{inner_name}] Computing entropy")
            pre["entropy"] = entropy_shannon(inner)

            if kind in ("pe", "elf"):
                cb(f"[{inner_name}] FLOSS: deobfuscating strings")
                floss_result = floss_strings(inner)
                if (floss_result.get("stdout") or "").strip():
                    pre["floss_result"] = floss_result
            cb(f"[{inner_name}] Extracting strings")
            pre["strings_preview"] = strings_preview_text(inner)

            # Run the appropriate analysis for the promoted kind
            if kind == "pe":
                cb(f"[{inner_name}] Authenticode verification")
                pre["authenticode_verify"] = authenticode_verify(inner)
                cb(f"[{inner_name}] objdump: PE headers/sections")
                pre["mandatory_objdump_pe_headers"] = objdump_pe_headers(inner)
                cb(f"[{inner_name}] objdump: PE imports")
                pre["mandatory_objdump_pe_dynamic"] = objdump_pe_imports_dynamic(inner)
                cb(f"[{inner_name}] radare2: analysis")
                pre["mandatory_radare2_info"] = radare2_quick_json(inner)
                cb(f"[{inner_name}] radare2: entry disasm")
                pre["mandatory_radare2_entry"] = radare2_entry_disasm(inner)
                cb(f"[{inner_name}] PE section entropy")
                pre["mandatory_pe_section_entropy"] = pe_section_entropy(inner)
                cb(f"[{inner_name}] .NET metadata analysis")
                pre["mandatory_dotnet_analysis"] = dotnet_analysis(inner)
                cb(f"[{inner_name}] binwalk: embedded signature scan")
                pre["mandatory_binwalk"] = binwalk_scan(inner)
                if options.get("use_ghidra"):
                    cb(f"[{inner_name}] Ghidra: full scan (this takes a while…)")
                    pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(inner)

            elif kind == "elf":
                cb(f"[{inner_name}] readelf: full headers")
                pre["mandatory_readelf_all"] = readelf_all(inner)
                cb(f"[{inner_name}] objdump: ELF dynamic section")
                pre["mandatory_objdump_elf_dynamic"] = objdump_elf_dynamic(inner)
                cb(f"[{inner_name}] ldd: shared library deps")
                pre["mandatory_ldd_deps"] = ldd_deps(inner)
                cb(f"[{inner_name}] binwalk: embedded signature scan")
                pre["mandatory_binwalk"] = binwalk_scan(inner)
                if options.get("use_ghidra"):
                    cb(f"[{inner_name}] Ghidra: full scan (this takes a while…)")
                    pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(inner)

            elif kind == "office":
                cb(f"[{inner_name}] oledump: listing streams")
                pre["mandatory_oledump_list"] = oledump_list(inner)
                cb(f"[{inner_name}] olevba: extracting VBA")
                pre["mandatory_olevba_json"] = olevba_json(inner)
                cb(f"[{inner_name}] oleobj: extracting objects")
                pre["mandatory_oleobj_extract"] = oleobj_extract(inner)
                pre["mandatory_rtfobj_extract"] = rtfobj_extract(inner)
                pre["mandatory_oledump_details"] = oledump_details(inner)
                _office_pe_paths = (
                    list(pre["mandatory_oleobj_extract"].get("extracted_files") or []) +
                    list(pre["mandatory_rtfobj_extract"].get("extracted_files") or [])
                )
                _ghidra_office = _ghidra_on_extracted_pes(_office_pe_paths, options, cb, label=inner_name)
                if _ghidra_office:
                    pre["mandatory_ghidra_extracted_pes"] = _ghidra_office

            elif kind == "office_openxml":
                cb(f"[{inner_name}] Listing OpenXML contents")
                pre["mandatory_openxml_list"] = openxml_list(inner)
                cb(f"[{inner_name}] Extracting OpenXML contents")
                pre["mandatory_openxml_extract"] = openxml_extract(inner)
                _openxml_pe_paths = list(pre["mandatory_openxml_extract"].get("extracted_files") or [])
                _ghidra_openxml = _ghidra_on_extracted_pes(_openxml_pe_paths, options, cb, label=inner_name)
                if _ghidra_openxml:
                    pre["mandatory_ghidra_extracted_pes"] = _ghidra_openxml

            elif kind == "msi":
                cb(f"[{inner_name}] 7z: extracting MSI contents")
                msi = msi_extract(inner)
                pre["mandatory_msi_extract"] = msi
                if msi.get("pe_strings_preview"):
                    pre["strings_preview"] = msi["pe_strings_preview"][:12000]
                _msi_pes = [f["path"] for f in (msi.get("pe_files") or []) if f.get("path")][:5]
                if not _msi_pes and msi.get("largest_pe"):
                    _msi_pes = [msi["largest_pe"]]
                pre["mandatory_msi_pe_analysis"] = {}
                for _pe_path in _msi_pes:
                    _pe_name = Path(_pe_path).name
                    cb(f"[{inner_name}] MSI: authenticode/headers/entropy on {_pe_name}")
                    _pe_entry = {
                        "path": _pe_path,
                        "authenticode": authenticode_verify(_pe_path),
                        "pe_headers":   objdump_pe_headers(_pe_path),
                        "pe_entropy":   pe_section_entropy(_pe_path),
                    }
                    cb(f"[{inner_name}] MSI: .NET analysis on {_pe_name}")
                    _dotnet = dotnet_analysis(_pe_path)
                    if not (_dotnet.get("error", "").startswith("Not a .NET PE") or
                            _dotnet.get("error", "").startswith("dnfile")):
                        _pe_entry["dotnet_analysis"] = _dotnet
                    if options.get("use_ghidra"):
                        cb(f"[{inner_name}] MSI: Ghidra full scan on {_pe_name} (this takes a while…)")
                        _pe_entry["ghidra_malhaus"] = ghidra_malhaus(_pe_path)
                    pre["mandatory_msi_pe_analysis"][_pe_name] = _pe_entry

            elif kind == "pdf":
                cb(f"[{inner_name}] PDF: keyword analysis")
                pre["mandatory_pdf_analysis"] = pdf_analysis(inner)

            elif kind == "lnk":
                cb(f"[{inner_name}] LNK: parsing shortcut")
                pre["mandatory_lnk_analysis"] = lnk_analysis(inner)

            elif kind == "jar":
                cb(f"[{inner_name}] JAR: reading MANIFEST.MF")
                pre["mandatory_jar_manifest"] = jar_manifest(inner)
                cb(f"[{inner_name}] JAR: listing class files")
                pre["mandatory_jar_class_list"] = jar_class_list(inner)
                cb(f"[{inner_name}] JAR: verifying signature")
                pre["mandatory_jarsigner_verify"] = jarsigner_verify(inner)
                cb(f"[{inner_name}] JAR: extracting inner files")
                pre["mandatory_jar_extract"] = jar_extract_inner(inner)
                cb(f"[{inner_name}] JAR: disassembling classes (javap)")
                pre["mandatory_javap_disasm"] = javap_disasm(inner)

            elif kind in ("vbs", "hta", "ps1", "shell", "js"):
                cb(f"[{inner_name}] Reading {kind} script content")
                try:
                    pre["mandatory_script_content"] = Path(inner).read_text(errors="replace")[:20000]
                except Exception as e:
                    pre["mandatory_script_content"] = f"read error: {e}"

        else:
            # Extraction failed or no recognizable payload found inside the archive.
            # Entropy and strings belong to the compressed/encrypted container — not the payload.
            # Flag this so downstream analysis doesn't misattribute container entropy.
            pre["archive_extraction_failed"] = True
            pre["analysis_note"] = (
                "Archive could not be promoted to an inner payload. "
                "Entropy and strings reflect the compressed/encrypted container, not the actual content. "
                "Results may be unreliable — resubmit with the correct password if encrypted."
            )
            if arc.get("pe_strings_preview"):
                pre["strings_preview"] = arc["pe_strings_preview"][:12000]

    _code_links_step(pre, sample, cb)
    _installer_step(pre, sample, cb, options)
    _phishing_step(pre, sample, cb)
    _network_artifacts_step(pre, sample, cb)
    return pre


def _code_links_step(pre: Dict[str, Any], sample: str, cb) -> None:
    """radare2 string->function links (registry/path/URL/command/JSON strings + the APIs each function
    reaches) for PE/ELF — seconds, so it also runs on every sub-component, Ghidra or not."""
    if pre.get("kind") not in ("pe", "elf"):
        return
    target = pre.get("effective_sample") or sample
    cb("radare2: linking strings to the functions that use them")
    pre["mandatory_code_links"] = code_links(target)


def _installer_step(pre: Dict[str, Any], sample: str, cb, options: Dict[str, Any] | None = None) -> None:
    """Inno Setup / NSIS installers keep the real payload compressed — unpack it statically."""
    target = pre.get("effective_sample") or sample
    if pre.get("kind") != "pe":
        return
    det = detect_installer(target)
    if not det:
        return
    cb(f"Installer detected ({det['type']} {det.get('version', '')}) — unpacking bundled files")
    try:
        pre["mandatory_installer_extract"] = installer_extract(target)
    except Exception as e:
        pre["mandatory_installer_extract"] = {"ok": False, "installer": det["type"], "version": det.get("version", ""),
                                              "error": f"{type(e).__name__}: {e}", "stdout": ""}
        return
    # Ghidra on the bundled payload, not only on the installer runtime (which is all a plain Ghidra run sees)
    if (options or {}).get("use_ghidra"):
        import os as _os
        files = [f for f in (pre["mandatory_installer_extract"].get("files") or [])
                 if f.get("kind") == "pe" and f.get("path") and not Path(f["path"]).name.startswith("chunk")]
        # unsigned executables first (signed vendor runtime DLLs are the least interesting), then larger
        files.sort(key=lambda f: (_pe_is_signed(f["path"]), not f["path"].lower().endswith(".exe"), -f.get("size", 0)))
        cap = int(_os.environ.get("MALHAUS_GHIDRA_PAYLOAD_MAX", "2") or 2)
        res = _ghidra_on_extracted_pes([f["path"] for f in files], options or {}, cb, label="installer payload", cap=cap)
        if res:
            pre.setdefault("mandatory_ghidra_extracted_pes", {}).update(res)


def _pe_is_signed(path: str) -> bool:
    try:
        import pefile
        return bool(pefile.PE(path, fast_load=True).OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
    except Exception:  # noqa: BLE001
        return False


PHISHING_KINDS = ("pdf", "office_openxml", "email")


def _phishing_step(pre: Dict[str, Any], sample: str, cb) -> None:
    """Content-level phishing analysis for documents and e-mails (also OOXML that file(1) labels "office")."""
    target = pre.get("effective_sample") or sample
    kind = pre.get("kind")
    try:
        with open(target, "rb") as fh:
            is_zip = fh.read(2) == b"PK"
    except OSError:
        is_zip = False
    if kind not in PHISHING_KINDS and not (kind == "office" and is_zip):
        return
    if kind == "email":
        cb("E-mail: parsing headers, body, links and attachments")
        try:
            pre["mandatory_email_parse"] = email_parse(target)
        except Exception as e:
            pre["mandatory_email_parse"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "stdout": ""}
    cb("Phishing analysis: text, links, sender, domain age")
    try:
        pre["mandatory_phishing_analysis"] = phishing_analysis_scan(target, progress_cb=cb)
    except Exception as e:
        pre["mandatory_phishing_analysis"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "stdout": ""}


def _network_artifacts_step(pre: Dict[str, Any], sample: str, cb) -> None:
    """Whole-file network IOC scan on the analyzed file (promoted inner file for archives),
    plus decoded text other tools already produced (FLOSS, macros, scripts, PDF/LNK/JAR output)."""
    def _out(key: str) -> str:
        v = pre.get(key)
        if isinstance(v, dict):
            return (v.get("stdout") or "") + "\n" + (v.get("stderr") or "")
        return v if isinstance(v, str) else ""

    extra = {
        "floss": _out("floss_result"),
        "script_content": _out("mandatory_script_content"),
        "olevba": _out("mandatory_olevba_json"),
        "openxml_extract": _out("mandatory_openxml_extract"),
        "pdf_analysis": _out("mandatory_pdf_analysis"),
        "lnk_analysis": _out("mandatory_lnk_analysis"),
        "javap": _out("mandatory_javap_disasm"),
        "msi_pe_strings": (pre.get("mandatory_msi_extract") or {}).get("pe_strings_preview") or "",
        # decoded e-mail bodies / PDF+OOXML text are invisible to strings(1)
        "document_text": (pre.get("mandatory_phishing_analysis") or {}).get("document_text") or "",
        "installer_script": (pre.get("mandatory_installer_extract") or {}).get("install_script") or "",
        "document_links": "\n".join(l.get("href", "") for l in (pre.get("mandatory_phishing_analysis") or {}).get("links") or []),
    }
    target = pre.get("effective_sample") or sample
    cb("Network artifacts: URLs/domains/IPs + domain age")
    try:
        pre["mandatory_network_artifacts"] = network_artifacts_scan(target, extra_sources=extra)
    except Exception as e:
        pre["mandatory_network_artifacts"] = {"ok": False, "error": f"{type(e).__name__}: {e}", "stdout": ""}
