from pathlib import Path
from typing import Any, Dict

from tools.cli_tools import (
    guess_kind_from_fileinfo,
    file_info, sha256, entropy_shannon, strings_ascii, extract_payloads,
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
)

# Optional custom tools (won't break if not installed/enabled)
try:
    from custom_tools.ghidra_headless import ghidra_headless_summary  # type: ignore
except Exception:
    ghidra_headless_summary = None  # type: ignore



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
    preview = (strings_ascii(sample).get("stdout", "") or "")[:12000]

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

    if kind == "office_openxml":
        cb("Listing OpenXML contents")
        pre["mandatory_openxml_list"] = openxml_list(sample)
        cb("Extracting OpenXML contents")
        pre["mandatory_openxml_extract"] = openxml_extract(sample)

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
        if options.get("use_ghidra"):
            cb("Ghidra: full scan (this takes a while…)")
            pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(sample)

    if kind == "msi":
        cb("7z: extracting MSI contents")
        msi = msi_extract(sample)
        pre["mandatory_msi_extract"] = msi
        if msi.get("pe_strings_preview"):
            pre["strings_preview"] = msi["pe_strings_preview"][:12000]

    if kind == "pdf":
        cb("PDF: keyword analysis")
        pre["mandatory_pdf_analysis"] = pdf_analysis(sample)

    if kind == "lnk":
        cb("LNK: parsing shortcut")
        pre["mandatory_lnk_analysis"] = lnk_analysis(sample)

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
            depth = arc.get("nesting_depth", 0)
            depth_note = f" (nested {depth} level{'s' if depth != 1 else ''} deep)" if depth > 0 else ""
            cb(f"{inner_kind.upper()} found inside archive{depth_note} — promoting to full {inner_kind} analysis")
            pre["effective_sample"] = inner
            pre["container_kind"] = "archive"

            # UPX check for PE/ELF before anything else
            if inner_kind in ("pe", "elf"):
                cb(f"Checking extracted {inner_kind.upper()} for UPX")
                if upx_detect(inner):
                    pre["upx_packed"] = True
                    cb("Unpacking UPX from extracted file")
                    pre["upx_unpack"] = upx_unpack(inner)
                    if (pre["upx_unpack"] or {}).get("ok"):
                        cb("Re-detecting after UPX unpack")
                        fi_post = file_info(inner)
                        kind_post = guess_kind_from_fileinfo(fi_post.get("stdout", ""), inner)
                        if kind_post not in ("unknown", ""):
                            inner_kind = kind_post
                else:
                    pre["upx_packed"] = False

            kind = inner_kind
            pre["kind"] = kind

            # Recompute entropy and strings on the promoted file
            cb(f"Computing entropy of extracted {kind}")
            pre["entropy"] = entropy_shannon(inner)

            if kind in ("pe", "elf"):
                cb("FLOSS: deobfuscating strings in extracted file")
                floss_result = floss_strings(inner)
                if (floss_result.get("stdout") or "").strip():
                    pre["floss_result"] = floss_result
            cb("Extracting strings from extracted file")
            pre["strings_preview"] = (strings_ascii(inner).get("stdout", "") or "")[:12000]

            # Run the appropriate analysis for the promoted kind
            if kind == "pe":
                cb("Authenticode verification (extracted PE)")
                pre["authenticode_verify"] = authenticode_verify(inner)
                cb("objdump: PE headers/sections")
                pre["mandatory_objdump_pe_headers"] = objdump_pe_headers(inner)
                cb("objdump: PE imports")
                pre["mandatory_objdump_pe_dynamic"] = objdump_pe_imports_dynamic(inner)
                cb("radare2: analysis")
                pre["mandatory_radare2_info"] = radare2_quick_json(inner)
                cb("radare2: entry disasm")
                pre["mandatory_radare2_entry"] = radare2_entry_disasm(inner)
                cb("PE section entropy")
                pre["mandatory_pe_section_entropy"] = pe_section_entropy(inner)
                cb(".NET metadata analysis")
                pre["mandatory_dotnet_analysis"] = dotnet_analysis(inner)
                if options.get("use_ghidra"):
                    cb("Ghidra: full scan of extracted PE…")
                    pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(inner)

            elif kind == "elf":
                cb("readelf: full headers")
                pre["mandatory_readelf_all"] = readelf_all(inner)
                cb("objdump: ELF dynamic section")
                pre["mandatory_objdump_elf_dynamic"] = objdump_elf_dynamic(inner)
                cb("ldd: shared library deps")
                pre["mandatory_ldd_deps"] = ldd_deps(inner)
                if options.get("use_ghidra"):
                    cb("Ghidra: full scan of extracted ELF…")
                    pre["mandatory_ghidra_malhaus"] = ghidra_malhaus(inner)

            elif kind == "office":
                cb("oledump: listing streams")
                pre["mandatory_oledump_list"] = oledump_list(inner)
                cb("olevba: extracting VBA")
                pre["mandatory_olevba_json"] = olevba_json(inner)
                cb("oleobj: extracting objects")
                pre["mandatory_oleobj_extract"] = oleobj_extract(inner)
                pre["mandatory_rtfobj_extract"] = rtfobj_extract(inner)
                pre["mandatory_oledump_details"] = oledump_details(inner)

            elif kind == "office_openxml":
                cb("Listing OpenXML contents")
                pre["mandatory_openxml_list"] = openxml_list(inner)
                cb("Extracting OpenXML contents")
                pre["mandatory_openxml_extract"] = openxml_extract(inner)

            elif kind == "msi":
                cb("7z: extracting MSI contents")
                msi = msi_extract(inner)
                pre["mandatory_msi_extract"] = msi
                if msi.get("pe_strings_preview"):
                    pre["strings_preview"] = msi["pe_strings_preview"][:12000]

            elif kind == "pdf":
                cb("PDF: keyword analysis")
                pre["mandatory_pdf_analysis"] = pdf_analysis(inner)

            elif kind == "lnk":
                cb("LNK: parsing shortcut")
                pre["mandatory_lnk_analysis"] = lnk_analysis(inner)

            elif kind in ("vbs", "hta", "ps1", "shell", "js"):
                cb(f"Reading {kind} script content")
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

    return pre
