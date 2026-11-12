"""
Recursive analysis of sub-components: files found inside the sample (installer payloads, archive
members, MSI contents, e-mail attachments, embedded Office objects, carved payloads...).

Every supported inner file gets the same preflight tooling as a top-level upload plus the
deterministic heuristic score; nested containers are followed up to MALHAUS_SUBCOMPONENT_DEPTH.
No LLM verdict loop runs per child (cost) — the parent's verdict LLM sees every child's chain,
score and reasons, and can call tools on any child via "path".

The result is stored as pre["mandatory_subcomponents"] (a normal tool-output dict with "stdout"),
so it appears in tools_used / tool_outputs without changing the JSON layout.
"""
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from tools.cli_tools import EXTRACT_DIR, _sha256_file, file_info, guess_kind_from_fileinfo

SUPPORTED = {"pe", "elf", "office", "office_openxml", "ps1", "shell", "js", "msi", "pdf", "lnk",
             "vbs", "hta", "archive", "email", "jar"}
# cheap, high-signal kinds first; big binaries last
_KIND_PRIO = {"ps1": 0, "vbs": 0, "hta": 0, "js": 0, "shell": 0, "lnk": 0, "office": 1, "office_openxml": 1,
              "pdf": 2, "email": 2, "archive": 3, "jar": 3, "msi": 4, "pe": 5, "elf": 5}
# extraction dirs shared by all samples — never walk them (their per-call "extracted_files" lists are used)
_SHARED_DIRS = {"oleobj", "openxml", "rtfobj"}
_SEP = " ▸ "  # ▸
_TOOL_OUT_CAP = 15000     # chars of one child tool output kept for the report
_CHILD_OUT_CAP = 60000    # per child
_TOTAL_OUT_CAP = 800000   # all children together


def _cfg(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _under_extract(p: Path) -> bool:
    try:
        p.resolve().relative_to(EXTRACT_DIR.resolve())
        return True
    except (ValueError, OSError):
        return False


def collect_children(pre: Dict[str, Any]) -> List[Path]:
    """Every file under extracted/ that this preflight's tools reported (paths in any result) or wrote into
    their own per-sample extraction directory (extract_dir / output_dir)."""
    files: Dict[str, Path] = {}

    def add_file(s: str) -> None:
        if len(s) > 4096 or not s.startswith("/"):
            return
        p = Path(s)
        try:
            if p.is_file() and _under_extract(p):
                files[str(p.resolve())] = p
        except OSError:
            pass

    def add_dir(s: str) -> None:
        p = Path(s)
        try:
            if not (p.is_dir() and _under_extract(p)) or p.resolve() == EXTRACT_DIR.resolve() \
                    or p.name in _SHARED_DIRS:
                return
            for f in list(p.rglob("*"))[:2000]:
                if f.is_file():
                    files[str(f.resolve())] = f
        except OSError:
            pass

    def walk(v: Any, key: str = "", depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "mandatory_subcomponents":
                    continue
                walk(x, str(k), depth + 1)
        elif isinstance(v, (list, tuple)):
            for x in v[:2000]:
                walk(x, key, depth + 1)
        elif isinstance(v, str):
            if key in ("extract_dir", "output_dir"):
                add_dir(v)
            elif key in ("path", "promoted_file", "largest_pe", "extracted_files", "pe_files", "files",
                         "script_files", "attachments", "extracted"):
                add_file(v)

    walk(pre)
    return list(files.values())


def _is_signed_pe(p: Path) -> bool:
    try:
        import pefile
        pe = pefile.PE(str(p), fast_load=True)
        return bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
    except Exception:  # noqa: BLE001
        return False


def _display_path(p: Path) -> str:
    """Path inside the container, without the extracted/<workdir>/ prefix."""
    try:
        rel = p.resolve().relative_to(EXTRACT_DIR.resolve())
        parts = rel.parts[1:] if len(rel.parts) > 1 else rel.parts
        return "/".join(parts)
    except ValueError:
        return p.name


def _child_tools(cpre: Dict[str, Any]) -> List[str]:
    return sorted(k for k, v in cpre.items() if isinstance(v, dict) and (k.startswith("mandatory_") or k in (
        "authenticode_verify", "floss_result", "extraction", "entropy")))


def analyze_subcomponents(pre: Dict[str, Any], sample: str, options: Optional[Dict[str, Any]] = None,
                          progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
    from agent.heuristics import heuristic_score_from_evidence
    from agent.postprocess import _authenticode_verified
    from agent.preflight import preflight
    from agent.suspicious import build_evidence_pack

    cb = progress_cb or (lambda m: None)
    opts = dict(options or {})
    opts["use_ghidra"] = False  # minutes per binary; Ghidra stays on the top-level sample
    max_depth = _cfg("MALHAUS_SUBCOMPONENT_DEPTH", 3)
    max_items = _cfg("MALHAUS_SUBCOMPONENT_MAX", 20)
    llm_left = [_cfg("MALHAUS_SUBCOMPONENT_LLM", 8)]  # strings-LLM passes for the highest-priority children
    budget = _cfg("MALHAUS_SUBCOMPONENT_SECONDS", 300)
    t_end = time.time() + budget

    root_name = Path(sample).name
    seen: Set[str] = set()
    try:
        seen.add(_sha256_file(Path(sample)))
        if pre.get("effective_sample"):
            seen.add(_sha256_file(Path(pre["effective_sample"])))
    except OSError:
        pass
    # Inner files hang off the container itself; the promoted file (analysed by the main pipeline) is
    # named separately so siblings are not shown as if they were inside it.
    root_chain = root_name
    promoted = ""
    if pre.get("effective_sample") and pre["effective_sample"] != sample:
        promoted = root_name + _SEP + _display_path(Path(pre["effective_sample"]))

    items: List[Dict[str, Any]] = []
    skipped = {"unsupported": 0, "duplicate": 0, "limit": 0}

    def visit(cpre: Dict[str, Any], chain: str, depth: int) -> None:
        if depth > max_depth:
            return
        queue = []
        for f in collect_children(cpre):
            try:
                if f.stat().st_size == 0:
                    continue
                h = _sha256_file(f)
            except OSError:
                continue
            if h in seen:
                skipped["duplicate"] += 1
                continue
            kind = guess_kind_from_fileinfo(file_info(str(f)).get("stdout", ""), str(f))
            if kind not in SUPPORTED:
                skipped["unsupported"] += 1
                continue
            seen.add(h)
            signed = kind == "pe" and _is_signed_pe(f)
            queue.append((_KIND_PRIO.get(kind, 9), signed, f.stat().st_size, f, kind, h))
        queue.sort(key=lambda q: q[:3])
        for _prio, _signed, size, f, kind, h in queue:
            if len(items) >= max_items or time.time() > t_end:
                skipped["limit"] += 1
                continue
            sub_chain = chain + _SEP + _display_path(f)
            cb(f"Sub-component {len(items) + 1}: {sub_chain} ({kind})")
            node: Dict[str, Any] = {"chain": sub_chain, "path": str(f), "kind": kind, "sha256": h, "size": size,
                                    "depth": depth, "score": 0, "risk_hint": "unknown", "reasons": [], "tools": []}
            items.append(node)
            try:
                cpre = preflight(str(f), options=opts, progress_cb=lambda m, c=sub_chain: None)
                if cpre.get("analysis_abort"):
                    node["reasons"] = [f"not analysed: {cpre.get('analysis_abort_reason', 'aborted')}"]
                    continue
                ev = build_evidence_pack(cpre, options=opts)
                strings_llm: Dict[str, Any] = {}
                if llm_left[0] > 0 and (cpre.get("strings_preview") or "").strip():
                    llm_left[0] -= 1
                    try:
                        import config
                        from agent.strings_llm import analyze_strings_llm
                        strings_llm = analyze_strings_llm(
                            model=config.LLM_MODEL_STRINGS or config.LLM_MODEL_VERDICT, kind=cpre.get("kind", kind),
                            file_entropy=(cpre.get("entropy") or {}).get("entropy"),
                            strings_preview=cpre["strings_preview"], max_chars=8000,
                            progress_cb=lambda m: None, context_note=f"This file was found inside {chain}.")
                        if strings_llm.get("error"):
                            strings_llm = {}
                    except Exception:  # noqa: BLE001 - deterministic score still applies
                        strings_llm = {}
                hz = heuristic_score_from_evidence(ev, strings_llm)
                verified = cpre.get("kind") == "pe" and _authenticode_verified(cpre)
                net = (cpre.get("mandatory_network_artifacts") or {})
                has_net = any(it.get("class") not in ("benign_infra", "loopback", "reserved", "private")
                              for it in net.get("items") or [])
                score = int(hz.get("score") or 0)
                node.update({
                    "kind": cpre.get("kind", kind),
                    "raw_score": score,
                    # same rule as the top-level benign guard: verified signature and no real network IOCs
                    "score": 0 if (verified and not has_net and score < 70) else score,
                    "signed_verified": bool(verified),
                    "reasons": [r for r in (hz.get("reasons") or []) if "Strings Analyst LLM" not in r][:6],
                    "network": (net.get("summary") or "")[:400],
                    "tools": _child_tools(cpre),
                    "strings_llm_score": strings_llm.get("strings_score") if strings_llm else None,
                })
                if strings_llm.get("summary"):
                    node["reasons"].append(f"Strings LLM: {str(strings_llm['summary'])[:240]}")
                if cpre.get("effective_sample") and cpre["effective_sample"] != str(f):
                    node["kind"] = f"{kind}→{cpre.get('kind', '?')}"  # e.g. archive→ps1 (promoted member)
                s = node["score"]
                node["risk_hint"] = "likely_malware" if s >= 70 else "suspicious" if s >= 40 else \
                    "unknown" if s >= 15 else "benign"
                if cpre.get("effective_sample"):
                    try:
                        seen.add(_sha256_file(Path(cpre["effective_sample"])))
                    except OSError:
                        pass
                outs, used = {}, 0
                for k, v in cpre.items():
                    if k == "mandatory_subcomponents":
                        continue
                    if isinstance(v, dict):
                        txt = (v.get("stdout") or v.get("stderr") or "").strip()
                    elif isinstance(v, str) and k.startswith("mandatory_"):  # e.g. mandatory_script_content
                        txt = v.strip()
                    else:
                        continue
                    if not txt or used > _CHILD_OUT_CAP:
                        continue
                    txt = txt[:_TOOL_OUT_CAP]
                    outs[k] = (txt, isinstance(v, str))
                    used += len(txt)
                node["_outputs"] = outs
                visit(cpre, sub_chain, depth + 1)
            except Exception as e:  # noqa: BLE001 - one bad child must not break the parent analysis
                node["reasons"] = [f"sub-analysis failed: {type(e).__name__}: {e}"]

    visit(pre, root_chain, 1)

    worst = max(items, key=lambda n: n["score"], default=None)
    flagged = [n for n in items if n["score"] >= 40]
    lines = [f"Sub-components analysed: {len(items)} (depth <= {max_depth})"
             + (f"; skipped: {skipped['limit']} over limit ({max_items} files / {budget}s)" if skipped["limit"] else "")
             + (f", {skipped['unsupported']} unsupported type" if skipped["unsupported"] else "")
             + (f", {skipped['duplicate']} duplicate" if skipped["duplicate"] else "")]
    if promoted:
        _sh = (pre.get("sha256") or {}).get("stdout", "").splitlines()
        _psha = _sh[1].split()[0] if len(_sh) > 1 and _sh[1].split() else ""
        lines.append(f"Promoted file (main analysis above): {promoted}" + (f"  sha256={_psha}" if _psha else ""))
    if worst:
        lines.append(f"Worst: {worst['chain']} — score {worst['score']}/100 ({worst['risk_hint']})")
    lines.append("")
    for n in sorted(items, key=lambda n: -n["score"]):
        sig = " [signed, verified]" if n.get("signed_verified") else ""
        lines.append(f"[{n['score']:>3}] {n['risk_hint']:<14} {n['kind']:<14} {n['chain']}{sig}")
        if n.get("raw_score", n["score"]) != n["score"]:
            lines.append(f"      raw heuristic {n['raw_score']} cleared to {n['score']}: verified Authenticode signature "
                         "and no actionable network IOCs")
        lines.append("      basis: deterministic heuristics" + (
            f" + strings LLM ({n['strings_llm_score']}/100)" if n.get("strings_llm_score") is not None
            else " only (no strings LLM pass for this file)"))
        lines.append(f"      sha256={n['sha256']}  size={n['size']}  path={n['path']}")
        for r in n["reasons"][:4]:
            lines.append(f"      - {str(r)[:220]}")
        if n.get("network"):
            lines.append(f"      network: {n['network'][:220]}")
    return {
        "ok": True,
        "items": items,
        "analyzed": len(items),
        "skipped": skipped,
        "max_score": worst["score"] if worst else 0,
        "worst": worst["chain"] if worst else "",
        "flagged": len(flagged),
        "promoted": promoted,
        "stdout": "\n".join(lines),
    }


def llm_details(subs: Dict[str, Any], budget: int = 9000) -> str:
    """Excerpts of every child's tool outputs for the verdict LLM, worst children first."""
    out, left = [], budget
    for n in sorted(subs.get("items") or [], key=lambda n: -n.get("score", 0)):
        outs = n.get("_outputs") or {}
        if not outs or left <= 0:
            continue
        block = [f"### {n['chain']} ({n['kind']}, score {n['score']}) path={n['path']}"]
        per = max(300, min(1500, left // 4) // max(1, len(outs)))
        for k, (txt, _is_str) in outs.items():
            block.append(f"[{k}] {txt[:per]}")
        s = "\n".join(block)[:max(0, left)]
        out.append(s)
        left -= len(s)
    return "\n\n".join(out)


def merge_into_preflight(pre: Dict[str, Any], subs: Dict[str, Any]) -> List[str]:
    """Append each child's output to the parent's section of the same tool (same keys, same structure:
    only the "stdout" text grows, under a header naming the chain inside the object). Tools the parent
    did not run get their own entry holding only the sub-component sections. Returns those new keys.
    Run AFTER the parent's own scoring/verdict so child text is never read as the parent's."""
    added: List[str] = []
    total = 0
    for n in subs.get("items") or []:
        for k, (txt, is_str) in (n.pop("_outputs", None) or {}).items():
            if total > _TOTAL_OUT_CAP:
                break
            section = f"\n\n===== sub-component: {n['chain']} ({n['kind']}) =====\n{txt}"
            total += len(section)
            cur = pre.get(k)
            if isinstance(cur, dict):
                cur["stdout"] = (cur.get("stdout") or "") + section
            elif isinstance(cur, str):  # text-valued tool output stays a string
                pre[k] = cur + section
            elif k not in pre:
                # same type the key has everywhere else: text tools stay strings, tool results dicts
                pre[k] = section.lstrip("\n") if is_str else {"ok": True, "stdout": section.lstrip("\n")}
                added.append(k)
    for n in subs.get("items") or []:
        n.pop("_outputs", None)
    return added


def apply_to_heuristics(heuristics: Dict[str, Any], subs: Dict[str, Any]) -> Dict[str, Any]:
    """The parent scores at least as high as its worst sub-component (+ a little per extra flagged one)."""
    if not subs or not subs.get("items"):
        return heuristics
    worst = max(subs["items"], key=lambda n: n["score"])
    if worst["score"] < 40:
        return heuristics
    extra = min(10, 3 * (subs.get("flagged", 1) - 1))
    new = min(100, max(int(heuristics.get("score") or 0), worst["score"] + extra))
    reasons = list(heuristics.get("reasons") or [])
    why = "; ".join(str(r) for r in worst["reasons"][:2])
    reasons.insert(0, f"Sub-component {worst['chain']} scored {worst['score']}/100 ({worst['risk_hint']})"
                      + (f": {why}" if why else "")
                      + (f" — {subs['flagged']} flagged sub-components in total" if subs.get("flagged", 0) > 1 else ""))
    heuristics = dict(heuristics)
    heuristics["score"] = new
    heuristics["reasons"] = reasons[:12]
    heuristics["risk_hint"] = "likely_malware" if new >= 70 else "suspicious" if new >= 40 else \
        "unknown" if new >= 15 else "benign"
    return heuristics
