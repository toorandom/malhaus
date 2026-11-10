import subprocess, os, json, re, base64, hashlib
from pathlib import Path
from shutil import which
from typing import Dict, Any, List, Optional

import pefile

TIMEOUT = 120
MAX = 450000

BASE_DIR = Path(__file__).resolve().parents[1]
TOOLS_DIR = BASE_DIR / "tools"
EXTRACT_DIR = BASE_DIR / "extracted"
EXTRACT_DIR.mkdir(exist_ok=True)

def run(cmd: List[str], timeout: int = TIMEOUT, max_bytes: int = MAX) -> Dict[str, Any]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
        return {
            "cmd": " ".join(cmd),
            "stdout": p.stdout[:max_bytes].decode(errors="replace"),
            "stderr": p.stderr[:max_bytes].decode(errors="replace"),
            "rc": p.returncode,
            "ok": True,
        }
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "stdout": "", "stderr": "TIMEOUT", "rc": None, "ok": False}
    except Exception as e:
        return {"cmd": " ".join(cmd), "stdout": "", "stderr": f"EXCEPTION: {type(e).__name__}: {e}", "rc": None, "ok": False}


def run_jailed(cmd: List[str], sample_path: str, timeout: int = TIMEOUT, max_bytes: int = MAX) -> Dict[str, Any]:
    """
    Run cmd inside a firejail sandbox if available.
    - No network access (--net=none)
    - Cannot gain root (--noroot)
    - Isolated /tmp (--private-tmp)
    - Read-only filesystem except the sample file and extracted/ dir
    Falls back to plain run() if firejail is not installed.
    """
    if not which("firejail"):
        return run(cmd, timeout=timeout, max_bytes=max_bytes)

    sample = Path(sample_path).resolve()
    # firejail --whitelist restricts $HOME visibility: only whitelisted paths are
    # accessible. We must include the venv (oletools, floss, etc. live there) and
    # the tools/ dir, otherwise commands installed under $HOME show "command not found".
    jail_cmd = [
        "firejail",
        "--quiet",
        "--noprofile",
        "--net=none",
        "--noroot",
        "--private-tmp",
        f"--read-only={sample}",
        f"--whitelist={sample}",
        f"--whitelist={EXTRACT_DIR}",
        f"--whitelist={BASE_DIR / '.venv'}",
        f"--whitelist={TOOLS_DIR}",
        "--",
    ] + cmd
    return run(jail_cmd, timeout=timeout, max_bytes=max_bytes)

def tool(func):
    func.is_tool = True
    return func

# make authenticode_verify behave like other tools
try:
    authenticode_verify.is_tool = True
except Exception:
    pass

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

# Interpreted scripts with no dedicated pipeline (Perl/CGI, Python, Ruby, PHP, web shells, batch, ...)
# go to the generic "shell" script class: script_content + base64 payload extraction + LLM review.
_SCRIPT_EXTS = {
    ".sh", ".bash", ".zsh", ".ksh", ".csh", ".bat", ".cmd",
    ".pl", ".pm", ".cgi", ".fcgi", ".py", ".pyw", ".rb", ".lua", ".tcl", ".awk", ".r",
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
    ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asmx", ".cfm",
}

def script_kind_from_header(head: bytes, ext: str = "", fileinfo: str = "") -> Optional[str]:
    """Kind for an interpreted script, from its first bytes (shebang, <?php, <% ...), extension or
    file(1) description. None when it does not look like a script."""
    head = head.lstrip(b"\xef\xbb\xbf")  # UTF-8 BOM
    first = head.split(b"\n", 1)[0].lower()
    if first.startswith(b"#!"):
        if b"pwsh" in first or b"powershell" in first:
            return "ps1"
        if re.search(rb"\b(node|nodejs|deno|bun)\b", first):
            return "js"
        return "shell"
    hl = head[:512].lower()
    if hl.startswith((b"<?php", b"<?=")) or b"<?php" in hl or re.match(rb"\s*<%[@=!\s]", hl) \
            or b"<%@ page" in hl or b"<jsp:" in hl:
        return "shell"
    if ext in _SCRIPT_EXTS:
        return "shell"
    s = (fileinfo or "").lower()
    if re.search(r"\b(perl|python|ruby|php|tcl|lua|awk|node)\b.*script|script(,)? [\w-]*\s*text executable|"
                 r"dos batch file", s):
        return "shell"
    return None

def guess_kind_from_fileinfo(fileinfo_stdout: str, path: str) -> str:
    s = (fileinfo_stdout or "").lower()
    ext = Path(path).suffix.lower()
    if "pe32" in s or "ms-dos executable" in s:
        return "pe"
    # Read magic bytes once — used for both PE and ELF disambiguation
    try:
        with open(path, "rb") as _f:
            magic = _f.read(4)
    except OSError:
        magic = b""
    # UPX-compressed: check actual magic to distinguish PE from ELF
    if "upx compressed" in s:
        if magic[:2] == b"MZ":
            return "pe"
        if magic[:4] == b"\x7fELF":
            return "elf"
        return "pe"  # safe fallback
    # MZ magic → PE regardless of file(1) output
    if magic[:2] == b"MZ":
        return "pe"
    # DOS COM executables have no MZ header; treat as PE for analysis purposes
    if ext == ".com":
        return "pe"
    if "elf" in s or magic[:4] == b"\x7fELF":
        return "elf"
    if ext in (".eml", ".msg") or "outlook message" in s or "rfc 822 mail" in s or "smtp mail" in s:
        return "email"
    if "microsoft word" in s or "microsoft excel" in s or "microsoft powerpoint" in s or "ole 2" in s or "compound document" in s:
        return "office"
    if "zip" in s and ext in [".docx", ".xlsx", ".pptx"]:
        return "office_openxml"
    if "ooxml" in s:
        return "office"
    if ext == ".msi" or "installation database" in s or "windows installer" in s:
        return "msi"
    if ext == ".pdf" or "pdf document" in s:
        return "pdf"
    if ext == ".lnk" or "ms windows shortcut" in s:
        return "lnk"
    if ext in (".vbs", ".vbe") or "visual basic" in s:
        return "vbs"
    if ext == ".hta":
        return "hta"
    if ext == ".jar" or "java archive" in s or (ext == ".war") or (ext == ".ear"):
        return "jar"
    if ext in (".zip",) or "zip archive" in s:
        return "archive"
    if ext in (".7z",) or "7-zip archive" in s:
        return "archive"
    if ext in (".rar",) or "rar archive" in s:
        return "archive"
    if ext == ".ps1" or "powershell" in s:
        return "ps1"
    if ext in [".sh", ".bash"] or "shell script" in s:
        return "shell"
    if ext in [".js", ".mjs", ".cjs"] or "javascript" in s:
        return "js"
    # Perl/CGI, Python, Ruby, PHP, web shells...: shebang / markers / extension / file(1) wording
    try:
        with open(path, "rb") as _f:
            head = _f.read(1024)
    except OSError:
        head = b""
    if b"\x00" not in head[:1024]:
        sk = script_kind_from_header(head, ext, s)
        if sk:
            return sk
    return "unknown"


def _extract_signer_info(path: str) -> Dict[str, Any]:
    """
    Extract Authenticode signer details from the embedded PKCS#7 chain:
    - signer_cn / signer_org : leaf cert subject (who actually signed)
    - issuer_cn  / issuer_org : immediate issuer
    - is_self_signed          : True when subject == issuer (no trusted CA)
    - chain_depth             : number of certs in the embedded chain
    Returns {} on any error or if no signature is present.
    """
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if not sec.VirtualAddress or not sec.Size:
            return {}

        raw_pe = Path(path).read_bytes()
        pkcs7_blob = raw_pe[sec.VirtualAddress: sec.VirtualAddress + sec.Size]
        pkcs7_data = pkcs7_blob[8:]  # strip 8-byte WIN_CERTIFICATE header

        from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
        from cryptography.x509.oid import NameOID as _NameOID

        certs = _pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        if not certs:
            return {}

        # Find the leaf signing cert: the one whose subject is not the issuer of any other
        issuer_subjects = {c.issuer for c in certs}
        leaf = next((c for c in certs if c.subject not in issuer_subjects), certs[0])

        def _attr(name_obj, oid: Any) -> str:
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value or ""
            except Exception:
                return ""

        return {
            "signer_cn":     _attr(leaf.subject, _NameOID.COMMON_NAME),
            "signer_org":    _attr(leaf.subject, _NameOID.ORGANIZATION_NAME),
            "issuer_cn":     _attr(leaf.issuer,  _NameOID.COMMON_NAME),
            "issuer_org":    _attr(leaf.issuer,  _NameOID.ORGANIZATION_NAME),
            "is_self_signed": leaf.subject == leaf.issuer,
            "chain_depth":   len(certs),
        }
    except Exception:
        return {}


def _fetch_aia_certs(path: str) -> str | None:
    """
    Extract the Authenticode PKCS#7 blob from a PE, walk the certificate chain,
    follow AIA (Authority Information Access) caIssuers URLs to download any
    missing issuer certificates, and return a path to a temporary PEM bundle
    containing all fetched certs. Returns None if nothing was fetched or on error.
    This lets osslsigncode verify chains whose root CA is absent from the local store.
    """
    import tempfile, urllib.request, urllib.error
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if not sec.VirtualAddress or not sec.Size:
            return None

        # The security directory contains the PKCS#7 blob directly (not an RVA)
        raw_pe = Path(path).read_bytes()
        pkcs7_blob = raw_pe[sec.VirtualAddress: sec.VirtualAddress + sec.Size]
        # Strip the 8-byte WIN_CERTIFICATE header (dwLength, wRevision, wCertificateType)
        pkcs7_data = pkcs7_blob[8:]

        from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.x509.oid import ExtensionOID as _ExtOID
        from cryptography.hazmat.backends import default_backend as _be

        certs = _pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        fetched_pems: list[bytes] = []

        for cert in certs:
            try:
                aia = cert.extensions.get_extension_for_oid(_ExtOID.AUTHORITY_INFORMATION_ACCESS)
                for access in aia.value:
                    if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":  # caIssuers
                        url = access.access_location.value
                        try:
                            req = urllib.request.Request(url, headers={"User-Agent": "malhaus/1.0"})
                            with urllib.request.urlopen(req, timeout=10) as resp:
                                data = resp.read()
                            # Could be DER or PEM
                            if b"-----BEGIN" in data:
                                fetched_pems.append(data)
                            else:
                                # DER → PEM
                                issuer_cert = _x509.load_der_x509_certificate(data, _be())
                                from cryptography.hazmat.primitives.serialization import Encoding
                                fetched_pems.append(issuer_cert.public_bytes(Encoding.PEM))
                        except Exception:
                            pass
            except Exception:
                pass

        if not fetched_pems:
            return None

        tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        for pem in fetched_pems:
            tmp.write(pem + b"\n")
        # Also append system bundle so the full chain is available
        system_bundle = Path("/etc/ssl/certs/ca-certificates.crt")
        if system_bundle.exists():
            tmp.write(system_bundle.read_bytes())
        tmp.flush()
        tmp.close()
        return tmp.name
    except Exception:
        return None


def authenticode_verify(path: str) -> Dict:
    """
    Offline Authenticode verification (PE).
    First attempts verification with the system CA bundle. If that fails due to a
    missing issuer certificate, automatically fetches the required CA certs via AIA
    (Authority Information Access) URLs embedded in the signing certificate chain and
    retries. This handles common cases like Microsoft Root CA 2010/2011 being absent
    from the Linux system store.
    Status codes prepended to output:
      SIGNATURE_VERIFIED                              — full chain verified
      SIGNATURE_VERIFIED_WITH_AIA_CERTS               — verified after AIA fetch
      UNSIGNED                                        — no Authenticode signature
      SIGNATURE_PRESENT_DIGEST_OK_CHAIN_UNVERIFIABLE  — signed, digest matches, chain fails
      SIGNATURE_DIGEST_MISMATCH                       — signed but file was tampered
      SIGNATURE_VERIFICATION_FAILED                   — other failure
    """
    import re as _re

    def _run_verify(extra_args: list[str] = []) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["osslsigncode", "verify"] + extra_args + ["-in", path],
            capture_output=True, text=True, timeout=30,
        )

    def _classify(p: subprocess.CompletedProcess) -> tuple[str, str]:
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        if p.returncode == 0:
            return "SIGNATURE_VERIFIED", out
        if "No signature found" in out:
            return "UNSIGNED", out
        if "unable to get local issuer certificate" in out or "unable to get issuer certificate" in out:
            digests = _re.findall(r"(?:Current|Calculated) message digest\s*:\s*([0-9A-Fa-f]+)", out)
            if len(digests) >= 2 and len(set(digests)) == 1:
                return "SIGNATURE_PRESENT_DIGEST_OK_CHAIN_UNVERIFIABLE", out
            return "SIGNATURE_DIGEST_MISMATCH", out
        return "SIGNATURE_VERIFICATION_FAILED", out

    try:
        p = _run_verify()
        status, out = _classify(p)

        if status == "SIGNATURE_PRESENT_DIGEST_OK_CHAIN_UNVERIFIABLE":
            # Try to fix by fetching issuer certs via AIA
            aia_bundle = _fetch_aia_certs(path)
            if aia_bundle:
                try:
                    p2 = _run_verify(["-CAfile", aia_bundle])
                    status2, out2 = _classify(p2)
                    if status2 == "SIGNATURE_VERIFIED":
                        status = "SIGNATURE_VERIFIED_WITH_AIA_CERTS"
                        out = out2 + f"\n[AIA bundle used: {aia_bundle}]"
                finally:
                    try:
                        Path(aia_bundle).unlink(missing_ok=True)
                    except Exception:
                        pass

        return {
            "ok": status in ("SIGNATURE_VERIFIED", "SIGNATURE_VERIFIED_WITH_AIA_CERTS"),
            "status": status,
            "rc": p.returncode,
            "stdout": f"[osslsigncode status: {status}]\n" + out,
            "stderr": "",
        }
    except FileNotFoundError:
        return {"ok": False, "status": "OSSLSIGNCODE_NOT_INSTALLED", "rc": 127, "stdout": "", "stderr": "osslsigncode not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": "TIMEOUT", "rc": 124, "stdout": "", "stderr": "osslsigncode verify timed out"}

# ---------------- TYPE + UNIVERSAL ----------------

@tool
def file_info(path: str) -> Dict[str, Any]:
    return run_jailed(["file", "-b", path], path, timeout=15, max_bytes=40000)

@tool
def sha256(path: str) -> Dict[str, Any]:
    return run(["sha256sum", path], timeout=20, max_bytes=50000)

@tool
def strings_ascii(path: str) -> Dict[str, Any]:
    return run_jailed(["strings", "-a", "-n", "6", path], path, timeout=40, max_bytes=650000)

def _network_import_names(path: str) -> List[str]:
    """Imported symbol names (PE via pefile, ELF via objdump -T) for network-capability matching."""
    names: List[str] = []
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
        if magic[:2] == b"MZ":
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imp in entry.imports:
                    if imp.name:
                        names.append(imp.name.decode(errors="ignore"))
            pe.close()
        elif magic == b"\x7fELF":
            out = run_jailed(["objdump", "-T", path], path, timeout=30, max_bytes=400000).get("stdout", "")
            names = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{2,})(?:@\S+)?\s*$", out, re.M)
    except Exception:
        pass
    return names

def network_artifacts_scan(path: str, extra_sources: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Implementation behind the network_artifacts tool; preflight passes decoded text
    (FLOSS, macros, scripts, PDF/LNK analysis) as extra_sources."""
    from agent.network_iocs import extract_network_artifacts, lookup_domain_ages, summarize
    import config as _cfg

    sources = {
        "strings_ascii": run_jailed(["strings", "-a", "-n", "6", path], path,
                                    timeout=60, max_bytes=4000000).get("stdout", ""),
        "strings_utf16le": run_jailed(["strings", "-a", "-el", "-n", "6", path], path,
                                      timeout=60, max_bytes=2000000).get("stdout", ""),
    }
    for k, v in (extra_sources or {}).items():
        if v:
            sources[k] = v
    na = extract_network_artifacts(sources, _network_import_names(path))

    na["domain_ages"] = []
    if _cfg.DOMAIN_AGE_LOOKUP and na["domains"]:
        # URL hosts first — they are the most likely live endpoints
        # URL hosts first — they are the most likely live endpoints. Shared-hosting/abused
        # services are skipped: their age is the platform's, not the actor's.
        lookup = [i for i in na["items"] if i["type"] == "domain" and i["class"] == "unknown"]
        url_hosts = [i["value"] for i in lookup if any(i["value"] in u for u in na["urls"])]
        ordered = url_hosts + [i["value"] for i in lookup if i["value"] not in url_hosts]
        na["domain_ages"] = lookup_domain_ages(ordered, max_domains=_cfg.DOMAIN_AGE_MAX_DOMAINS,
                                               timeout=_cfg.DOMAIN_AGE_TIMEOUT)
        na["summary"] = summarize(na)

    lines = [na["summary"], ""]
    for it in na["items"]:
        lines.append(f"[{it['type']:<6}] {it['value']}  class={it['class']}  via={','.join(it['sources'])}")
        lines.append(f"         context: {it['context'][:160]}")
    for a in na["domain_ages"]:
        age = f"{a['age_days']} days old (registered {a['created']})" if a.get("age_days") is not None \
            else a.get("status") or a.get("error") or "registration date unknown"
        lines.append(f"[age   ] {a['domain']}: {age}  ({a.get('source', '')})")
    if na["network_apis"]:
        lines.append("")
        for cap, apis in na["network_apis"].items():
            lines.append(f"[api   ] {cap}: {', '.join(apis)}")
    na["ok"] = True
    na["stdout"] = "\n".join(lines)
    return na

@tool
def network_artifacts(path: str) -> Dict[str, Any]:
    """Static network IOC extraction (never executes the sample): scans full ASCII and UTF-16LE
    strings for URLs, domains, IPv4 and e-mails, rejects code identifiers like System.SysUtils or
    kernel32.dll, flags PKI/vendor hosts as benign infrastructure and known paste/tunnel/dyndns hosts
    as abused services, lists network-capable imports (wininet, winhttp, ws2_32, URLDownloadToFile...)
    and looks up the registration age of the domains found (RDAP/whois). Use it on extracted inner
    files (pass "path") to find C2 endpoints the container hides."""
    return network_artifacts_scan(path)

# ---------------- INSTALLERS (Inno Setup / NSIS) ----------------

# innoextract 1.9 (latest release, also what apt ships) understands setup data up to 6.0.5.
# The real ceiling is probed from `innoextract --version`; MALHAUS_INNOEXTRACT_MAX_VERSION overrides it.
INNOEXTRACT_MAX_VERSION = (6, 0, 5)
_INNO_LDR_ID = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"   # SetupLdrOffsetTable ID
_INNO_CHUNK_ID = b"zlb\x1a"                      # compressed file-data chunk

def _parse_version(s: str) -> Optional[tuple]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None

_IE_PROBE: Dict[str, Optional[tuple]] = {}
_RE_CALL_OP = re.compile(rb"[\xe8\xe9]")

def _innoextract_max(binary: str) -> tuple:
    """Highest Inno Setup version a given innoextract build supports ("... Inno Setup 1.2.10 to 6.0.5")."""
    env = _parse_version(os.environ.get("MALHAUS_INNOEXTRACT_MAX_VERSION", ""))
    if env:
        return env
    if binary not in _IE_PROBE:
        out = run([binary, "--version"], timeout=10, max_bytes=20000)
        m = re.search(r"to\s+(\d+\.\d+\.\d+)", (out.get("stdout", "") + out.get("stderr", "")))
        _IE_PROBE[binary] = _parse_version(m.group(1)) if m else None
    return _IE_PROBE[binary] or INNOEXTRACT_MAX_VERSION

def _inno_transform_calls(buf: bytes) -> bytes:
    """Undo Inno Setup's CALL/JMP address filter ([Version 3], applied to x86/x64 executables before
    compression): per 64 KiB block, E8/E9 followed by a 32-bit operand whose high byte is 00/FF had its
    low 24 bits made absolute. Inverse of TransformCallInstructions(Encode=False)."""
    p = bytearray(buf)
    n = len(p)
    find = _RE_CALL_OP.search
    for blk in range(0, n, 0x10000):
        end = min(blk + 0x10000, n) - 4
        i = blk
        while i < end:
            m = find(p, i, end)
            if not m:
                break
            i = m.start() + 1
            if p[i + 3] == 0x00 or p[i + 3] == 0xFF:
                addr = (i + 4) & 0xFFFFFF  # AddrOffset (= blk) + offset in block + 4 == file offset + 4
                rel = (p[i] | (p[i + 1] << 8) | (p[i + 2] << 16)) - addr
                if rel & 0x800000:
                    p[i + 3] ^= 0xFF
                p[i], p[i + 1], p[i + 2] = rel & 0xFF, (rel >> 8) & 0xFF, (rel >> 16) & 0xFF
            i += 4
    return bytes(p)

def _inno_offsets(data: bytes) -> Dict[str, int]:
    """Setup loader offset table: revision 1 (32-bit fields) or 2 (6.5+/7.x: 64-bit offsets)."""
    import struct
    o = data.find(_INNO_LDR_ID)
    if o < 0:
        return {}
    rev = struct.unpack_from("<I", data, o + 12)[0]
    try:
        if rev == 1:
            total, off_exe, _usz, _crc, off0, off1 = struct.unpack_from("<IIIiII", data, o + 16)
        elif rev == 2:
            total, off_exe, _usz, _crc, off0, off1 = struct.unpack_from("<qqIiqq", data, o + 16)
        else:
            return {"revision": rev}
    except struct.error:
        return {}
    return {"revision": rev, "offset0": off0, "offset1": off1, "total": total}

def _inno_decompress_chunk(data: bytes, pos: int, cap: int) -> tuple:
    """Decompress one zlb chunk at data[pos] (magic included). Inno stores LZMA2 (1-byte dict prop),
    LZMA1 (5-byte props), zlib or bzip2 behind the magic. Returns (bytes, method, compressed_len)."""
    import lzma, zlib as _zlib, bz2
    body_start = pos + 4
    b0 = data[body_start] if body_start < len(data) else 0xFF

    def _lzma(filters, skip):
        dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
        out = bytearray()
        i = body_start + skip
        while i < len(data) and not dec.eof and len(out) < cap:
            piece = data[i:i + (1 << 20)]
            try:
                out += dec.decompress(piece, max_length=cap - len(out))
            except lzma.LZMAError:
                break  # trailing garbage / truncated stream: keep what decoded
            i += len(piece)
            while not dec.eof and not dec.needs_input and len(out) < cap:
                out += dec.decompress(b"", max_length=cap - len(out))
        used = (i - len(dec.unused_data)) if dec.eof else i
        return bytes(out), used - pos

    attempts = []
    if b0 <= 40:
        dsz = (2 | (b0 & 1)) << (b0 // 2 + 11)
        attempts.append(("lzma2", lambda: _lzma([{"id": lzma.FILTER_LZMA2, "dict_size": dsz}], 1)))
    if b0 < 225:
        lc, r = b0 % 9, b0 // 9
        lp, pb = r % 5, r // 5
        dsz = int.from_bytes(data[body_start + 1:body_start + 5], "little")
        if lc + lp <= 4 and 4096 <= dsz <= (1 << 30):
            attempts.append(("lzma1", lambda: _lzma([{"id": lzma.FILTER_LZMA1, "dict_size": dsz,
                                                      "lc": lc, "lp": lp, "pb": pb}], 5)))
    if data[body_start:body_start + 1] == b"\x78":
        def _z():
            d = _zlib.decompressobj()
            out = d.decompress(data[body_start:body_start + cap], cap)
            return out, len(data[body_start:body_start + cap]) - len(d.unused_data) + 4
        attempts.append(("zlib", _z))
    if data[body_start:body_start + 3] == b"BZh":
        def _bz():
            d = bz2.BZ2Decompressor()
            out = d.decompress(data[body_start:body_start + cap], cap)
            return out, len(data[body_start:body_start + cap]) - len(d.unused_data) + 4
        attempts.append(("bzip2", _bz))
    for name, fn in attempts:
        try:
            out, used = fn()
        except Exception:  # noqa: BLE001
            continue
        if len(out) >= 64:
            return out, name, used
    return b"", "", 0

def _carve_pes(stream: bytes) -> List[Dict[str, Any]]:
    """PE files inside a decompressed Inno chunk (files are stored back to back). Executables get the
    call filter undone; the variant whose PE checksum verifies wins (else filtered for x86/x64)."""
    import struct
    found, pos = [], 0
    while len(found) < 200:
        s = stream.find(b"MZ", pos)
        if s < 0:
            break
        pos = s + 2
        try:
            lf = struct.unpack_from("<I", stream, s + 0x3C)[0]
            if not (0x40 <= lf <= 0x1000) or stream[s + lf:s + lf + 4] != b"PE\x00\x00":
                continue
            machine = struct.unpack_from("<H", stream, s + lf + 4)[0]
        except struct.error:
            continue
        # Image size from the section table / certificate table (header bytes are left intact by the
        # filter in practice; the filtered header is re-checked below)
        head = stream[s:s + 0x2000]
        try:
            hp = pefile.PE(data=_inno_transform_calls(head) if machine in (0x14C, 0x8664) else head, fast_load=True)
            size = max((sec.PointerToRawData + sec.SizeOfRawData for sec in hp.sections), default=0)
            sd = hp.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if sd.VirtualAddress and sd.Size and sd.VirtualAddress + sd.Size > size:
                size = sd.VirtualAddress + sd.Size
        except Exception:  # noqa: BLE001
            continue
        if not (0x200 <= size <= 200_000_000) or s + size > len(stream):
            continue
        window = stream[s:s + size]
        variants = [("filtered", _inno_transform_calls(window))] if machine in (0x14C, 0x8664) else []
        variants.append(("raw", window))
        best = None
        for label, buf in variants:
            try:
                pe = pefile.PE(data=buf, fast_load=True)
                end = max((sec.PointerToRawData + sec.SizeOfRawData for sec in pe.sections), default=0)
                sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # certificate table: file offset
                if sd.VirtualAddress and sd.Size and sd.VirtualAddress + sd.Size > end:
                    end = sd.VirtualAddress + sd.Size
                if end < 0x200 or end > len(buf):
                    continue
                img = buf[:end]
                pe2 = pefile.PE(data=img, fast_load=True)
                ok_sum = bool(pe2.OPTIONAL_HEADER.CheckSum) and pe2.generate_checksum() == pe2.OPTIONAL_HEADER.CheckSum
                cand = (ok_sum, label, img, pe2)
                if best is None or (ok_sum and not best[0]):
                    best = cand
                if ok_sum:
                    break
            except Exception:  # noqa: BLE001
                continue
        if not best:
            continue
        ok_sum, label, img, pe2 = best
        name = ""
        try:
            pe2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for fi in getattr(pe2, "FileInfo", []) or []:
                for entry in fi:
                    for st in getattr(entry, "StringTable", []) or []:
                        v = st.entries.get(b"OriginalFilename") or st.entries.get(b"InternalName")
                        if v and not name:
                            name = v.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        is_dll = bool(pe2.FILE_HEADER.Characteristics & 0x2000)
        found.append({"offset": s, "data": img, "machine": machine, "filter": label,
                      "checksum_ok": ok_sum, "name": name, "ext": ".dll" if is_dll else ".exe"})
        pos = s + len(img)
    return found

def _inno_builtin_extract(path: str, outdir: Path, notes: List[str]) -> int:
    """Recover the payload of Inno Setup installers innoextract cannot read (6.1+ / 7.x): decompress the
    zlb file-data chunks, carve the PE files (call filter undone, PE checksum verified) and keep the
    whole decompressed stream for strings / network scans. File names come from version info."""
    data = Path(path).read_bytes()
    cap = int(os.environ.get("MALHAUS_INNO_MAX_UNPACK_MB", "512")) * 1024 * 1024
    offs = _inno_offsets(data)
    if offs.get("revision") not in (None, 1, 2):
        notes.append(f"unknown setup loader revision {offs['revision']}; scanning for data chunks")
    if offs.get("offset1") == 0:
        notes.append("installer uses external setup-*.bin disk slices (DiskSpanning); payload not embedded")
    start = offs.get("offset1") or 0
    if start and data[start:start + 4] != _INNO_CHUNK_ID:
        start = 0
    carve_dir = outdir / "inno_carved"
    carve_dir.mkdir(parents=True, exist_ok=True)
    recovered, total_out, pos, n_chunk = 0, 0, start, 0
    while total_out < cap and n_chunk < 500:
        c = data.find(_INNO_CHUNK_ID, pos)
        if c < 0:
            break
        out, method, used = _inno_decompress_chunk(data, c, cap - total_out)
        if not out:
            pos = c + 4
            continue
        n_chunk += 1
        total_out += len(out)
        (carve_dir / f"chunk{n_chunk:03d}_{method}.bin").write_bytes(out)
        recovered += 1
        names_seen: Dict[str, int] = {}
        for pe_f in _carve_pes(out):
            base = re.sub(r"[^A-Za-z0-9._-]", "_", pe_f["name"])[:80] or f"carved_{pe_f['offset']:08x}{pe_f['ext']}"
            if not base.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi")):
                base += pe_f["ext"]
            names_seen[base] = names_seen.get(base, 0) + 1
            if names_seen[base] > 1:
                stem, ext = os.path.splitext(base)
                base = f"{stem}_{names_seen[base]}{ext}"
            (carve_dir / base).write_bytes(pe_f["data"])
            recovered += 1
        notes.append(f"chunk {n_chunk} @0x{c:x}: {method}, {len(out)} bytes decompressed")
        pos = c + max(used, 4)
    if recovered:
        notes.append("payload recovered by the built-in Inno decoder: PE files carved from the decompressed "
                     "stream (names from version info; install paths unavailable for this setup version), "
                     "chunk*.bin = full decompressed file data")
    return recovered

def detect_installer(path: str) -> Dict[str, Any]:
    """Cheap signature check: Inno Setup (setup data header) or NSIS (Nullsoft first-header magic)."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return {}
    m = re.search(rb"Inno Setup Setup Data \((\d+)\.(\d+)\.(\d+)\)", data)
    # the Inno runtime stub (Setup.e32 / SetupLdr.e32 shipped as a file) contains the ID string as a constant;
    # a real installer also has the setup loader offset table (or the pre-5.1.5 "Inno" header at 0x30)
    if m and (b"rDlPtS" in data or data[0x30:0x34] == b"Inno"):
        return {"type": "inno", "version": ".".join(x.decode() for x in m.groups()),
                "version_tuple": tuple(int(x) for x in m.groups())}
    if b"\xef\xbe\xad\xdeNullsoftInst" in data or b"\xef\xbe\xad\xdeNullSoftInst" in data:
        return {"type": "nsis", "version": ""}
    return {}

def _innoextract_bin() -> Optional[str]:
    """innoextract build supporting the newest Inno version: MALHAUS_INNOEXTRACT, tools/innoextract,
    /usr/local/bin (custom builds) or PATH."""
    cands = [os.environ.get("MALHAUS_INNOEXTRACT", ""), str(TOOLS_DIR / "innoextract"),
             "/usr/local/bin/innoextract", which("innoextract") or ""]
    found = [c for c in dict.fromkeys(cands) if c and Path(c).is_file() and os.access(c, os.X_OK)]
    return max(found, key=_innoextract_max) if found else None

@tool
def installer_extract(path: str) -> Dict[str, Any]:
    """Statically unpack an Inno Setup (innoextract) or NSIS (7z, includes the [NSIS].nsi install script)
    installer and inventory the bundled files (type, size, sha256, entropy). Installers hide the real payload
    in compressed data — use the listed paths with other tools ("path") to analyse what would be installed."""
    det = detect_installer(path)
    if not det:
        return {"ok": False, "stdout": "", "error": "not an Inno Setup or NSIS installer"}
    outdir = _work_dir(path, det["type"])
    res: Dict[str, Any] = {"ok": False, "installer": det["type"], "version": det.get("version", ""),
                           "extract_dir": str(outdir), "files": []}
    if det["type"] == "inno":
        notes: List[str] = []
        ie = _innoextract_bin()
        ie_max = _innoextract_max(ie) if ie else INNOEXTRACT_MAX_VERSION
        ie_dir = outdir / "innoextract"
        if not ie:
            notes.append("innoextract not installed")
        elif det["version_tuple"] > ie_max:
            notes.append(f"Inno Setup {det['version']} is newer than innoextract supports (<= {'.'.join(map(str, ie_max))})")
        else:
            ie_dir.mkdir(parents=True, exist_ok=True)
            r = run_jailed([ie, "-e", "-q", "-d", str(ie_dir), path], path, timeout=180, max_bytes=200000)
            notes.append("innoextract: " + (r.get("stdout", "") + r.get("stderr", "")).strip()[-1500:])
        if not any(f.is_file() for f in ie_dir.rglob("*")) if ie_dir.exists() else True:
            # 1) built-in decoder (zlb chunks -> carved PEs), works for 6.1+ / 7.x
            try:
                got = _inno_builtin_extract(path, outdir, notes)
            except Exception as e:  # noqa: BLE001
                got = 0
                notes.append(f"built-in Inno decoder failed: {type(e).__name__}: {e}")
            # 2) last resort: 7z opens the PE; only the zlb blob it yields is payload, the rest is
            #    sections/resources of the stub — decode the blob, never report the stub parts as payload
            if not got:
                raw7 = _work_dir(path, "inno7z")
                run_jailed(["7z", "x", "-y", "-bd", f"-o{raw7}", path], path, timeout=180, max_bytes=20000)
                for blob in [f for f in raw7.rglob("*") if f.is_file()]:
                    with open(blob, "rb") as fh:
                        if fh.read(4) == _INNO_CHUNK_ID:
                            got += _inno_builtin_extract(str(blob), outdir, notes)
                if not got:
                    notes.append("7z fallback: only stub sections/resources, no payload chunk recovered")
            if not got:
                res["error"] = (f"Inno Setup {det['version']}: payload not unpacked (innoextract unsupported/failed, "
                                "built-in decoder and 7z found no decodable data chunk) — the installed files were "
                                "NOT examined; dynamic analysis (detonation) recommended")
        res["tool_output"] = "\n".join(notes)[-3000:]
    else:
        r = run_jailed(["7z", "x", "-y", "-bd", f"-o{outdir}", path], path, timeout=180, max_bytes=200000)
        res["tool_output"] = (r.get("stdout", "") + r.get("stderr", ""))[-3000:]
        if not r.get("ok"):
            res["error"] = "7z NSIS extraction failed: " + (r.get("stderr", "") or "")[-500:]

    files = [f for f in sorted(outdir.rglob("*")) if f.is_file()
             and (det["type"] != "inno" or not f.relative_to(outdir).parts[0].startswith("inno7z"))][:300]
    for f in files:
        size = f.stat().st_size
        data = f.read_bytes() if size <= 20_000_000 else b""
        res["files"].append({
            "path": str(f), "name": str(f.relative_to(outdir)), "size": size,
            "kind": guess_kind_from_fileinfo(file_info(str(f)).get("stdout", ""), str(f)),
            "sha256": _sha256_bytes(data) if data else "", "entropy": round(_shannon_entropy(data), 3) if data else None,
        })
    res["ok"] = bool(res["files"])
    pes = [f for f in res["files"] if f["kind"] == "pe"]
    if pes:
        res["largest_pe"] = max(pes, key=lambda f: f["size"])["path"]
    nsi = next((f for f in files if f.suffix.lower() == ".nsi"), None)
    if nsi:
        res["install_script"] = nsi.read_text(errors="replace")[:40000]

    lines = [f"{det['type']} installer {det.get('version', '')}".strip() + f" — {len(res['files'])} file(s) extracted to {outdir}"]
    if res.get("error"):
        lines.append(f"! {res['error']}")
    if det["type"] == "inno" and res.get("tool_output"):
        lines += ["  " + l for l in res["tool_output"].splitlines()[:20]]
    for f in res["files"][:120]:
        lines.append(f"  {f['kind']:<14} {f['size']:>10}  H={f['entropy']}  {f['name']}  path={f['path']}")
    if res.get("install_script"):
        lines += ["", "=== install script ([NSIS].nsi) ===", res["install_script"][:8000]]
    res["stdout"] = "\n".join(lines)
    return res

# ---------------- DOCUMENT / E-MAIL CONTENT (phishing) ----------------

def _work_dir(path: str, tag: str) -> Path:
    d = EXTRACT_DIR / f"{tag}_{_sha256_file(Path(path))[:16]}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _ocr_pages(path: str, outdir: Path, pages: str = "1-3") -> Dict[str, Any]:
    """Render PDF pages to PNG (mutool) and OCR them with tesseract when installed;
    otherwise return the images so the vision LLM can transcribe them."""
    res: Dict[str, Any] = {"page_images_b64": [], "text": "", "method": ""}
    if not which("mutool"):
        return res
    run_jailed(["mutool", "draw", "-q", "-r", "110", "-o", str(outdir / "page%d.png"), path, pages],
               path, timeout=90, max_bytes=20000)
    imgs = sorted(outdir.glob("page*.png"))[:3]
    if which("tesseract"):
        texts = [run(["tesseract", str(p), "stdout"], timeout=90, max_bytes=200000).get("stdout", "") for p in imgs]
        if "".join(texts).strip():
            res["text"], res["method"] = "\n\f".join(texts), "tesseract"
            return res
    res["page_images_b64"] = [base64.b64encode(p.read_bytes()).decode() for p in imgs if p.stat().st_size < 4_000_000]
    return res

_IMG_MAGIC = ((b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
              (b"BM", "bmp"), (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"))
_IMG_EXT = (".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp", ".webp", ".tif", ".tiff")
_RE_DATA_IMG = re.compile(r"data:image/(png|jpe?g|gif|bmp|webp)(?:;[\w=.-]+)*;base64,([A-Za-z0-9+/=\s]{200,})", re.I)

def _image_type(data: bytes) -> str:
    for magic, t in _IMG_MAGIC:
        if data.startswith(magic):
            return t
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return ""

def _add_image(images: List[Dict[str, Any]], data: bytes, name: str, source: str) -> None:
    """Queue an embedded image (e-mail inline part, attachment, data: URI, OOXML media) for OCR."""
    if not data or len(data) < 600 or len(data) > 15_000_000 or len(images) >= 60:
        return
    if not _image_type(data):
        return
    h = _sha256_bytes(data)
    if any(i["sha256"] == h for i in images):
        return
    images.append({"name": str(name)[:160], "source": source, "sha256": h, "data": data})

def _add_html_data_images(images: List[Dict[str, Any]], html: str, source: str) -> None:
    for n, m in enumerate(_RE_DATA_IMG.finditer(html or "")):
        try:
            data = base64.b64decode(re.sub(r"\s+", "", m.group(2)), validate=False)
        except (ValueError, base64.binascii.Error):
            continue
        _add_image(images, data, f"data-uri-{n + 1}.{m.group(1).lower()}", source)

_ZBAR_ARGS: Optional[List[str]] = None

def _zbar_decode(png: Path) -> List[str]:
    """QR/barcode payloads in an image (zbarimg). --nodbus (silences the D-Bus socket warning in
    containers) is only passed when this zbarimg build supports it; older builds reject the flag."""
    global _ZBAR_ARGS
    if _ZBAR_ARGS is None:
        helptext = run(["zbarimg", "--help"], timeout=10, max_bytes=20000)
        _ZBAR_ARGS = ["zbarimg", "--quiet", "--raw"] + (
            ["--nodbus"] if "--nodbus" in helptext.get("stdout", "") + helptext.get("stderr", "") else [])
    out = run(_ZBAR_ARGS + [str(png)], timeout=30, max_bytes=20000).get("stdout", "")
    return [l.strip() for l in out.splitlines() if l.strip()]

def _ocr_embedded_images(images: List[Dict[str, Any]], outdir: Path) -> Dict[str, Any]:
    """OCR embedded images (phishing text/buttons rendered as pictures to dodge text filters) and decode
    QR codes. Each image is normalised to PNG with Pillow (first GIF frame, small images upscaled);
    tracking pixels, spacers and small icons are skipped. Without tesseract the PNGs are returned so the
    vision LLM can transcribe them."""
    out: Dict[str, Any] = {"images": [], "pending_b64": [], "skipped": 0}
    if not images:
        return out
    try:
        from PIL import Image, ImageOps
    except ImportError:
        out["error"] = "Pillow not installed"
        return out
    imgdir = outdir / "embedded_images"
    imgdir.mkdir(parents=True, exist_ok=True)
    has_tess, has_zbar = bool(which("tesseract")), bool(which("zbarimg"))
    max_ocr = int(os.environ.get("MALHAUS_IMAGE_OCR_MAX", "12"))
    for img in images:
        if len(out["images"]) >= max_ocr:
            out["skipped"] += 1
            continue
        try:
            import io
            with Image.open(io.BytesIO(img["data"])) as im:
                w, h = im.size
                if w * h > 40_000_000:
                    out["skipped"] += 1
                    continue
                if w < 60 or h < 20 or w * h < 6000:  # tracking pixel / spacer / bullet icon
                    out["skipped"] += 1
                    continue
                im.seek(0)
                im = ImageOps.exif_transpose(im.convert("RGBA" if "A" in im.getbands() or im.mode == "P" else "RGB"))
                if im.mode == "RGBA":  # transparent text on white, not black
                    bg = Image.new("RGB", im.size, "white")
                    bg.paste(im, mask=im.split()[-1])
                    im = bg
                # Original resolution for QR decoding: resampling blurs module edges and breaks zbarimg.
                orig_png = imgdir / f"{img['sha256'][:16]}_orig.png"
                im.save(orig_png, "PNG")
                # Rescaled copy for tesseract, which reads small text better when upscaled.
                scale = 2 if max(w, h) < 800 else (0.5 if max(w, h) > 5000 else 1)
                png = orig_png
                if scale != 1:
                    im = im.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
                    png = imgdir / f"{img['sha256'][:16]}.png"
                    im.save(png, "PNG")
        except Exception:  # noqa: BLE001 - corrupt / unsupported image
            out["skipped"] += 1
            continue
        row = {"name": img["name"], "source": img["source"], "sha256": img["sha256"], "width": w, "height": h,
               "text": "", "method": "", "qr": []}
        if has_zbar:
            qr = _zbar_decode(orig_png)
            if not qr and png != orig_png:  # e.g. a tiny QR that only decodes once enlarged
                qr = _zbar_decode(png)
            row["qr"] = qr[:5]
        if has_tess:
            txt = run(["tesseract", str(png), "stdout"], timeout=60, max_bytes=100000).get("stdout", "")
            row["text"], row["method"] = re.sub(r"\n\s*\n+", "\n", txt).strip(), "tesseract"
        else:
            # vision LLM: original unless it was downscaled (huge image); upscaling only adds tokens
            vis = png if scale < 1 else orig_png
            if vis.stat().st_size < 4_000_000:
                row["method"] = "pending_vision"
                out["pending_b64"].append((len(out["images"]), base64.b64encode(vis.read_bytes()).decode()))
        out["images"].append(row)
    return out

def _attach_image_ocr(doc: Dict[str, Any], images: List[Dict[str, Any]], outdir: Path) -> None:
    res = _ocr_embedded_images(images, outdir)
    doc["image_ocr"] = res["images"]
    doc["image_ocr_pending_b64"] = res["pending_b64"]
    doc["image_ocr_skipped"] = res["skipped"]
    if res.get("error"):
        doc["image_ocr_error"] = res["error"]

def _pdf_content(path: str) -> Dict[str, Any]:
    doc: Dict[str, Any] = {"format": "pdf", "text": "", "links": [], "text_method": "none"}
    outdir = _work_dir(path, "pdfdoc")
    if which("mutool"):
        doc["text"] = run_jailed(["mutool", "draw", "-q", "-F", "txt", "-o", "-", path], path,
                                 timeout=90, max_bytes=400000).get("stdout", "")
        doc["text_method"] = "text_layer"
        clean = outdir / "decompressed.pdf"
        run_jailed(["mutool", "clean", "-d", path, str(clean)], path, timeout=90, max_bytes=20000)
        raw = clean.read_bytes() if clean.exists() else Path(path).read_bytes()
    else:
        raw = Path(path).read_bytes()
    for m in re.finditer(rb"/URI\s*\(((?:\\.|[^\\)])*)\)", raw):
        doc["links"].append({"href": m.group(1).decode("latin-1").replace("\\/", "/"), "text": ""})
    for m in re.finditer(rb"/URI\s*<([0-9A-Fa-f\s]+)>", raw):
        try:
            doc["links"].append({"href": bytes.fromhex(m.group(1).decode().replace(" ", "")).decode("latin-1"), "text": ""})
        except ValueError:
            pass
    # AcroForm text field with the password flag (Ff bit 14 = 8192)
    doc["forms"] = [{"action": "", "password": True}] if re.search(rb"/FT\s*/Tx[^>]*/Ff\s+8192", raw) else []
    has_images = re.search(rb"/Subtype\s*/Image", raw) is not None
    if len(re.sub(r"\s+", "", doc["text"])) < 200 and has_images:
        ocr = _ocr_pages(path, outdir)
        if ocr["text"]:
            doc["text"], doc["text_method"] = ocr["text"], ocr["method"]
        else:
            doc["needs_ocr"] = True
            doc["page_images_b64"] = ocr["page_images_b64"]
    elif has_images and which("tesseract"):
        # Text layer present, but a lure (fake button, QR code, "view document" banner) may be an image:
        # OCR the rendered pages and keep only lines the text layer does not already contain.
        ocr = _ocr_pages(path, outdir)
        known = re.sub(r"\W+", "", doc["text"].lower())
        new = [l.strip() for l in (ocr.get("text") or "").splitlines()
               if len(re.sub(r"\W+", "", l)) >= 4 and re.sub(r"\W+", "", l.lower()) not in known]
        if new:
            doc["image_ocr"] = [{"name": "rendered pages 1-3", "source": "pdf page images", "sha256": "",
                                 "width": 0, "height": 0, "text": "\n".join(new)[:20000], "method": "tesseract", "qr": []}]
    if has_images and which("zbarimg") and which("mutool"):
        pages = sorted(outdir.glob("page*.png")) or []
        if not pages:
            run_jailed(["mutool", "draw", "-q", "-r", "110", "-o", str(outdir / "page%d.png"), path, "1-3"],
                       path, timeout=90, max_bytes=20000)
            pages = sorted(outdir.glob("page*.png"))[:3]
        qr = [q for p in pages for q in _zbar_decode(p)]
        if qr:
            doc.setdefault("image_ocr", []).append({"name": "rendered pages 1-3", "source": "pdf QR code", "sha256": "",
                                                    "width": 0, "height": 0, "text": "", "method": "zbarimg", "qr": qr[:10]})
    return doc

def _openxml_content(path: str) -> Dict[str, Any]:
    import zipfile
    import html as _html
    doc: Dict[str, Any] = {"format": "openxml", "text": "", "links": [], "text_method": "xml"}
    parts: List[str] = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()

        def _read(n: str) -> str:
            return z.read(n).decode("utf-8", "replace") if z.getinfo(n).file_size < 20_000_000 else ""

        rels: Dict[str, Dict[str, str]] = {}
        for n in names:
            if n.endswith(".rels"):
                for m in re.finditer(r"<Relationship\b([^>]*)/?>", _read(n)):
                    a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
                    if a.get("TargetMode") == "External":
                        rels[a.get("Id", "")] = a
                        if a.get("Type", "").endswith(("/attachedTemplate", "/oleObject")):
                            doc.setdefault("remote_templates", []).append(a.get("Target", ""))
        text_parts = [n for n in names if re.match(
            r"(word/(document|header\d*|footer\d*|footnotes|comments)|ppt/slides/slide\d+|xl/sharedStrings)\.xml$", n)]
        for n in text_parts:
            xml = _read(n)
            # hyperlink visible text -> target (rels Id lookup)
            for hm in re.finditer(r'<w:hyperlink\b[^>]*r:id="([^"]+)"[^>]*>(.*?)</w:hyperlink>', xml, re.S):
                tgt = rels.get(hm.group(1), {}).get("Target")
                if tgt:
                    doc["links"].append({"href": tgt, "text": "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", hm.group(2)))})
            xml = re.sub(r"</w:p>|</a:p>|</si>", "\n", xml)
            parts.append(re.sub(r"<[^>]+>", "", xml))
        linked = {l["href"] for l in doc["links"]}
        for a in rels.values():
            t = a.get("Target", "")
            if t and t not in linked and not t.startswith("mailto:"):
                doc["links"].append({"href": t, "text": ""})
        images: List[Dict[str, Any]] = []
        for n in names:
            if re.match(r"(word|ppt|xl)/(media|embeddings)/", n) and n.lower().endswith(_IMG_EXT) \
                    and z.getinfo(n).file_size < 15_000_000:
                _add_image(images, z.read(n), n, "embedded media")
    doc["text"] = _html.unescape(re.sub(r"\n\s*\n+", "\n\n", "\n".join(parts))).strip()
    _attach_image_ocr(doc, images, _work_dir(path, "ooxml"))
    return doc

def _msg_props(ole, prefix: str = "") -> Dict[str, Any]:
    """MAPI string/binary properties (__substg1.0_PPPPTTTT) of an Outlook .msg storage."""
    props: Dict[str, Any] = {}
    for entry in ole.listdir(streams=True, storages=False):
        if (prefix and (len(entry) != 2 or entry[0] != prefix)) or (not prefix and len(entry) != 1):
            continue
        name = entry[-1]
        if not name.startswith("__substg1.0_"):
            continue
        tag, typ = name[12:16].upper(), name[16:20].upper()
        data = ole.openstream(entry).read()
        if typ == "001F":
            props[tag] = data.decode("utf-16-le", "replace").rstrip("\x00")
        elif typ == "001E":
            props[tag] = data.decode("latin-1", "replace").rstrip("\x00")
        elif typ == "0102":
            props[tag] = data
    return props

def _email_content(path: str, ocr_images: bool = True) -> Dict[str, Any]:
    from email import policy
    from email.parser import BytesParser, HeaderParser
    from email.utils import getaddresses, parseaddr
    from agent.phishing import html_to_text_and_links
    from agent.network_iocs import RE_URL

    outdir = _work_dir(path, "email")
    images: List[Dict[str, Any]] = []
    email_d: Dict[str, Any] = {"attachments": []}
    text, html_body = "", ""
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head.startswith(b"\xd0\xcf\x11\xe0"):  # OLE -> Outlook .msg
        import olefile
        email_d["format"] = "msg"
        ole = olefile.OleFileIO(path)
        p = _msg_props(ole)
        hdrs = HeaderParser().parsestr(p.get("007D", "") or "")  # PR_TRANSPORT_MESSAGE_HEADERS
        email_d.update({
            "subject": p.get("0037", ""), "from_name": p.get("0C1A", "") or p.get("0042", ""),
            "from": p.get("5D01", "") or p.get("0C1F", "") or p.get("0065", ""),
            "to": p.get("0E04", ""), "message_id": p.get("1035", ""),
            "reply_to": parseaddr(hdrs.get("Reply-To", ""))[1], "return_path": hdrs.get("Return-Path", "").strip("<> "),
            "date": hdrs.get("Date", ""), "authentication_results": " ".join(hdrs.get_all("Authentication-Results") or []),
            "received_spf": hdrs.get("Received-SPF", ""), "x_originating_ip": hdrs.get("X-Originating-IP", ""),
            "received": hdrs.get_all("Received") or [],
        })
        if "@" not in email_d["from"] and hdrs.get("From"):
            email_d["from_name"], email_d["from"] = parseaddr(hdrs.get("From"))
        text = p.get("1000", "") if isinstance(p.get("1000"), str) else ""
        hb = p.get("1013", "")
        html_body = hb.decode("utf-8", "replace") if isinstance(hb, bytes) else hb
        for st in sorted({e[0] for e in ole.listdir(streams=True, storages=False) if e[0].startswith("__attach_version1.0_")}):
            ap = _msg_props(ole, st)
            name = ap.get("3707") or ap.get("3704") or st
            data = ap.get("3701") if isinstance(ap.get("3701"), bytes) else b""
            email_d["attachments"].append({"name": name, "data": data})
        ole.close()
    else:
        email_d["format"] = "eml"
        with open(path, "rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
        from_name, from_addr = parseaddr(str(msg.get("From", "")))
        email_d.update({
            "subject": str(msg.get("Subject", "")), "from_name": from_name, "from": from_addr,
            "to": ", ".join(a for _, a in getaddresses([str(x) for x in msg.get_all("To") or []])),
            "reply_to": parseaddr(str(msg.get("Reply-To", "")))[1], "return_path": str(msg.get("Return-Path", "")).strip("<> "),
            "date": str(msg.get("Date", "")), "message_id": str(msg.get("Message-ID", "")),
            "authentication_results": " ".join(str(x) for x in msg.get_all("Authentication-Results") or []),
            "received_spf": str(msg.get("Received-SPF", "")), "x_originating_ip": str(msg.get("X-Originating-IP", "")),
            "received": [str(x) for x in msg.get_all("Received") or []],
        })
        email_d["dkim_domains"] = sorted(set(re.findall(
            r"\bd=([A-Za-z0-9.-]+)", " ".join(str(x) for x in msg.get_all("DKIM-Signature") or []))))
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            fname = part.get_filename()
            if ctype.startswith("image/") and not fname and part.get_content_disposition() != "attachment":
                # inline (cid:) image without a filename: not an attachment, but still OCR it
                cid = str(part.get("Content-ID", "")).strip("<> ") or "inline"
                _add_image(images, part.get_payload(decode=True) or b"", f"cid:{cid}", "inline image")
                continue
            if fname or part.get_content_disposition() == "attachment":
                email_d["attachments"].append({"name": fname or "unnamed", "data": part.get_payload(decode=True) or b""})
            elif ctype == "text/plain" and not text:
                text = part.get_content()
            elif ctype == "text/html" and not html_body:
                html_body = part.get_content()

    links: List[Dict[str, str]] = []
    forms: List[Dict[str, Any]] = []
    if html_body:
        html_text, links, forms = html_to_text_and_links(html_body)
        text = text or html_text
        _add_html_data_images(images, html_body, "html body data: URI")
    linked = {l["href"] for l in links}
    links += [{"href": u, "text": ""} for u in RE_URL.findall(text or "") if u not in linked]

    # Save attachments so other tools (and the LLM via "path") can analyse them
    saved = []
    for a in email_d.pop("attachments"):
        data = a.pop("data") or b""
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(str(a["name"])).name)[:120] or "attachment"
        dest = outdir / safe
        dest.write_bytes(data)
        saved.append({"name": a["name"], "size": len(data), "sha256": _sha256_bytes(data), "path": str(dest)})
        if _image_type(data):  # attached / inline (.msg) picture: often the whole lure or a QR code
            _add_image(images, data, a["name"], "image attachment")
        if safe.lower().endswith((".html", ".htm", ".svg")):
            att_html = data.decode("utf-8", "replace")
            _, att_links, att_forms = html_to_text_and_links(att_html)
            links += att_links
            forms += att_forms
            _add_html_data_images(images, att_html, f"data: URI in {a['name']}")
    email_d["attachments"] = saved
    email_d["body_html"] = html_body[:200000]
    doc = {"format": email_d["format"], "text": (text or "")[:100000], "links": links, "forms": forms,
           "text_method": "email_body", "email": email_d}
    if ocr_images:
        _attach_image_ocr(doc, images, outdir)
    else:
        doc["embedded_image_count"] = len(images)
    return doc

def document_content_scan(path: str) -> Dict[str, Any]:
    """Text, links and (for e-mail) sender/attachments of a PDF, OOXML document, .eml or .msg."""
    with open(path, "rb") as fh:
        head = fh.read(8)
    ext = Path(path).suffix.lower()
    try:
        if head.startswith(b"%PDF") or ext == ".pdf":
            return _pdf_content(path)
        if head.startswith(b"PK"):
            return _openxml_content(path)
        if ext in (".eml", ".msg") or head.startswith(b"\xd0\xcf\x11\xe0") or re.match(rb"^[A-Za-z-]+:", head):
            return _email_content(path)
    except Exception as e:
        return {"format": ext.lstrip(".") or "unknown", "text": "", "links": [], "error": f"{type(e).__name__}: {e}"}
    return {"format": "unknown", "text": "", "links": [], "error": "unsupported format for content scan"}

def _fmt_email(e: Dict[str, Any]) -> List[str]:
    lines = []
    for k in ("from_name", "from", "reply_to", "return_path", "to", "subject", "date", "message_id",
              "x_originating_ip", "authentication_results", "received_spf"):
        if e.get(k):
            lines.append(f"{k:<22} {str(e[k])[:300]}")
    for a in e.get("attachments") or []:
        lines.append(f"attachment             {a['name']}  ({a['size']} bytes, sha256 {a['sha256'][:16]}…)  path={a['path']}")
    return lines

@tool
def email_parse(path: str) -> Dict[str, Any]:
    """Parse an .eml or Outlook .msg e-mail: sender (From/display name/Reply-To/Return-Path), SPF/DKIM/DMARC
    results, Received chain, subject, decoded body text, links (visible text vs real href) and attachments.
    Attachments are saved to disk and their paths listed — run other tools on them with "path"."""
    doc = _email_content(path, ocr_images=False)  # OCR of embedded images happens in phishing_analysis
    e = doc.get("email") or {}
    lines = _fmt_email(e)
    if doc.get("embedded_image_count"):
        lines.append(f"embedded images        {doc['embedded_image_count']} (OCR'd by phishing_analysis)")
    lines += ["", f"links ({len(doc['links'])}):"] + [f"  {l['href'][:200]}  text='{l['text'][:80]}'" for l in doc["links"][:60]]
    lines += ["", "body:", (doc.get("text") or "")[:6000]]
    return {"ok": True, "stdout": "\n".join(lines), "email": {k: v for k, v in e.items() if k != "body_html"},
            "links": doc["links"], "attachments": e.get("attachments", []), "text": doc.get("text", "")}

def phishing_analysis_scan(path: str, progress_cb=None, use_llm: bool = True) -> Dict[str, Any]:
    from agent.phishing import analyze_phishing
    doc = document_content_scan(path)
    res = analyze_phishing(doc, progress_cb=progress_cb, use_llm=use_llm)
    if doc.get("error"):
        res["notes"].append(f"content extraction: {doc['error']}")
    res["document_text"] = (doc.get("text") or "")[:20000]
    lines = [res["summary"], ""]
    if res.get("email"):
        lines += _fmt_email(res["email"]) + [""]
    lines.append(f"text: {res['text_chars']} chars via {res.get('text_method')}")
    for s in res["signals"]:
        lines.append(f"[+{s['weight']:>2}] {s['signal']}")
    for l in res["links"][:60]:
        lines.append(f"[link] {l['href'][:160]}" + (f"  text='{l['text'][:60]}'" if l["text"] else "") +
                     (f"  ! {'; '.join(l['flags'])}" if l["flags"] else ""))
    for r in res.get("image_ocr") or []:
        t = re.sub(r"\s+", " ", r.get("text") or "")[:300]
        lines.append(f"[img ] {r['name']} ({r['source']}, {r['width']}x{r['height']}, {r['method'] or 'no OCR'})"
                     + (f": {t}" if t else "") + (f"  QR: {', '.join(r['qr'])}" if r.get("qr") else ""))
    for a in res["domain_ages"]:
        lines.append(f"[age ] {a['domain']}: " + (f"{a['age_days']} days (registered {a['created']})"
                                                if a.get("age_days") is not None else (a.get("status") or a.get("error") or "unknown")))
    if res["llm"]:
        lines.append(f"[llm ] {json.dumps(res['llm'], ensure_ascii=False)[:1500]}")
    for n in res["notes"]:
        lines.append(f"[note] {n}")
    res["stdout"] = "\n".join(lines)
    return res

@tool
def phishing_analysis(path: str) -> Dict[str, Any]:
    """Phishing / social-engineering analysis of a PDF, DOCX/XLSX/PPTX, .eml or .msg: extracts the text
    (OCR or vision-LLM transcription for image-only PDFs and for pictures embedded in the e-mail/document,
    QR codes decoded), links with visible-text vs real-target mismatch,
    sender spoofing (display name, Reply-To/Return-Path, SPF/DKIM/DMARC), lookalike/brand-impersonating and
    newly registered domains (RDAP/whois age), risky attachments, credential forms and lure wording, then asks
    the LLM to judge the text. Use it on attachments or embedded documents via "path"."""
    return phishing_analysis_scan(path)

@tool
def ssdeep_hash(path: str) -> Dict[str, Any]:
    if which("ssdeep"):
        return run(["ssdeep", "-b", path], timeout=25, max_bytes=120000)
    return {"ok": False, "error": "ssdeep not installed"}

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p_i = c / n
            ent -= p_i * math.log2(p_i)
    return round(ent, 4)

@tool
def entropy_shannon(path: str) -> Dict[str, Any]:
    data = Path(path).read_bytes()
    return {"ok": True, "entropy": _shannon_entropy(data), "size": len(data)}

@tool
def pe_section_entropy(path: str) -> Dict[str, Any]:
    """Compute Shannon entropy per PE section. Entropy > 7.0 on executable sections suggests packing or encryption."""
    try:
        pe = pefile.PE(path, fast_load=False)
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode(errors="replace").rstrip("\x00").strip()
            data = sec.get_data()
            ent = _shannon_entropy(data)
            executable = bool(sec.Characteristics & 0x20000000)
            writable   = bool(sec.Characteristics & 0x80000000)
            sections.append({
                "name": name,
                "entropy": ent,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "executable": executable,
                "writable": writable,
                "suspicious": ent > 7.0 and executable,
            })
        return {"ok": True, "sections": sections}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------- PE (more low-level visibility) ----------------

def upx_detect(path: str) -> bool:
    """Return True if the PE appears to be UPX-packed (uses `upx -t`)."""
    if not which("upx"):
        # Fallback: check for UPX section names in raw bytes
        try:
            data = Path(path).read_bytes()
            return b"UPX0" in data or b"UPX1" in data
        except Exception:
            return False
    result = run_jailed(["upx", "-t", path], path, timeout=30, max_bytes=4096)
    return result.get("rc") == 0

@tool
def upx_unpack(path: str) -> Dict[str, Any]:
    """Decompress a UPX-packed PE in-place using `upx -d`. Returns ok=True on success."""
    if not which("upx"):
        return {"ok": False, "error": "upx not installed"}
    # upx -d modifies the file in-place — run_jailed passes --read-only on the sample
    # which prevents upx from writing the unpacked data back. Use run() directly instead.
    result = run(["upx", "-d", path], timeout=60, max_bytes=65000)
    # run() sets ok=True when the process ran without exception, but upx can exit non-zero
    # (e.g. already unpacked, corrupt binary). Treat rc != 0 as a failed unpack.
    result["ok"] = result.get("rc") == 0
    result["unpacked_path"] = path
    return result

@tool
def ghidra_malhaus(path: str) -> Dict[str,Any]:
    ghidra_m = TOOLS_DIR / "ghidra_malhaus"
    if not ghidra_m.exists():
        return {"ok": False, "error": f"ghidra_malhaus was not found {ghidra_m}"}
    print("Running ghidra_malhaus over: " + path)
    # Run in a new process group so JVM signals (SIGTERM etc.) don't reach
    # the gunicorn worker process and crash it.
    import os as _os
    try:
        p = subprocess.Popen(
            [str(ghidra_m), path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**_os.environ.copy(), "LC_ALL": "C", "LANG": "C"},
            start_new_session=True,
        )
        stdout, stderr = p.communicate(timeout=600)
        max_bytes = 650000
        return {
            "cmd": f"{ghidra_m} {path}",
            "stdout": stdout[:max_bytes].decode(errors="replace"),
            "stderr": stderr[:max_bytes].decode(errors="replace"),
            "rc": p.returncode,
            "ok": True,
        }
    except subprocess.TimeoutExpired:
        p.kill(); p.communicate()
        return {"cmd": f"{ghidra_m} {path}", "stdout": "", "stderr": "TIMEOUT", "rc": None, "ok": False}
    except Exception as e:
        return {"cmd": f"{ghidra_m} {path}", "stdout": "", "stderr": f"EXCEPTION: {type(e).__name__}: {e}", "rc": None, "ok": False}


def dotnet_analysis(path: str) -> Dict[str, Any]:
    """
    Analyse a .NET PE file with dnfile.
    Extracts type/assembly/method references, .NET resources, and obfuscation
    indicators — things invisible to strings analysis when payloads are
    encrypted and loaded at runtime via Assembly.Load.
    """
    import math as _math, re as _re
    from collections import defaultdict as _dd

    try:
        import dnfile  # type: ignore
    except ImportError:
        return {"ok": False, "error": "dnfile not installed", "stdout": "", "stderr": "dnfile not installed", "rc": 1}

    try:
        dn = dnfile.dnPE(path)
    except Exception as e:
        return {"ok": False, "error": f"dnfile parse failed: {e}", "stdout": "", "stderr": str(e), "rc": 1}

    if not dn.net:
        return {"ok": False, "error": "Not a .NET PE", "stdout": "Not a .NET PE (no CLR header).", "stderr": "", "rc": 0}

    _SUSPICIOUS_NS = {
        "System.Management.Automation":           "powershell_execution",
        "System.Management.Automation.Runspaces": "powershell_execution",
        "Microsoft.Win32":                         "registry_access",
        "System.Reflection":                       "runtime_code_loading",
        "System.Reflection.Emit":                  "runtime_code_generation",
        "System.Runtime.InteropServices":          "native_interop",
        "System.Diagnostics.Process":             "process_creation",
        "System.Net":                              "network_access",
        "System.Net.Sockets":                      "raw_socket",
        "System.Security.Cryptography":            "crypto",
        "System.IO.Compression":                   "compression",
        "Microsoft.CSharp":                        "dynamic_code",
    }
    _SUSPICIOUS_TYPES = {
        "Assembly": "runtime_code_loading", "Activator": "runtime_code_loading",
        "DllImport": "native_interop", "Marshal": "native_interop",
        "WebClient": "network_download", "HttpClient": "network_access",
        "TcpClient": "raw_socket", "RegistryKey": "registry_access",
        "Process": "process_creation", "ProcessStartInfo": "process_creation",
        "Mutex": "mutex", "AesManaged": "crypto", "RijndaelManaged": "crypto",
        "RSACryptoServiceProvider": "crypto", "GZipStream": "compression",
        "PowerShell": "powershell_execution", "Runspace": "powershell_execution",
        "RunspaceFactory": "powershell_execution",
        "WindowsIdentity": "privilege_check", "WindowsPrincipal": "privilege_check",
        "Bitmap": "screenshot", "SendKeys": "input_simulation",
    }
    _SUSPICIOUS_METHODS = {
        "Load": "runtime_code_loading", "LoadFile": "runtime_code_loading",
        "LoadFrom": "runtime_code_loading", "CreateInstance": "runtime_code_loading",
        "InvokeMember": "reflection_invoke", "GetMethod": "reflection_invoke",
        "CreateProcess": "process_creation",
        "VirtualAlloc": "memory_injection", "VirtualAllocEx": "memory_injection",
        "WriteProcessMemory": "memory_injection",
        "CreateRemoteThread": "thread_injection", "NtCreateThreadEx": "thread_injection",
        "QueueUserAPC": "apc_injection", "SetWindowsHookEx": "hook_injection",
        "AddMpPreference": "av_exclusion", "ExclusionPath": "av_exclusion",
        "DisableRealtimeMonitoring": "av_disable",
    }

    def _shannon(s):
        if not s: return 0.0
        from collections import Counter
        freq = Counter(s)
        n = len(s)
        return -sum((f/n)*_math.log2(f/n) for f in freq.values())

    def _obfuscated(name):
        if not name or len(name) < 2: return False
        if _shannon(name) > 3.8 and len(name) >= 6: return True
        if _re.fullmatch(r'[a-zA-Z0-9]{1,4}', name): return True
        return False

    caps = _dd(set)
    lines = []
    obf_count = 0
    total_types = 0

    lines.append("== Assembly References ==")
    try:
        for row in (dn.net.mdtables.AssemblyRef or []):
            name = str(row.Name) if row.Name else ""
            ver = f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}"
            lines.append(f"  {name} v{ver}")
            for ns, cap in _SUSPICIOUS_NS.items():
                if name and ns.startswith(name):
                    caps[cap].add(f"AssemblyRef:{name}")
    except Exception as e:
        lines.append(f"  [error: {e}]")

    lines.append("\n== Suspicious Type References ==")
    seen: _dd = _dd(set)
    try:
        for row in (dn.net.mdtables.TypeRef or []):
            ns   = str(row.TypeNamespace) if row.TypeNamespace else ""
            name = str(row.TypeName) if row.TypeName else ""
            fqn  = f"{ns}.{name}" if ns else name
            total_types += 1
            if _obfuscated(name): obf_count += 1
            for sus_ns, cap in _SUSPICIOUS_NS.items():
                if ns.startswith(sus_ns) and fqn not in seen[cap]:
                    caps[cap].add(fqn); lines.append(f"  [{cap}] {fqn}"); seen[cap].add(fqn); break
            else:
                for sus_t, cap in _SUSPICIOUS_TYPES.items():
                    if name == sus_t and fqn not in seen[cap]:
                        caps[cap].add(fqn); lines.append(f"  [{cap}] {fqn}"); seen[cap].add(fqn); break
    except Exception as e:
        lines.append(f"  [error: {e}]")

    lines.append("\n== Suspicious Method References ==")
    seen_m: set = set()
    try:
        for row in (dn.net.mdtables.MemberRef or []):
            mname = str(row.Name) if row.Name else ""
            for sus_m, cap in _SUSPICIOUS_METHODS.items():
                if mname == sus_m and mname not in seen_m:
                    caps[cap].add(f"MemberRef:{mname}"); lines.append(f"  [{cap}] {mname}()"); seen_m.add(mname); break
    except Exception as e:
        lines.append(f"  [error: {e}]")

    lines.append("\n== .NET Resources ==")
    try:
        for res in (dn.net.resources or []):
            rname = str(res.name) if hasattr(res, "name") else "?"
            rsize = res.size if hasattr(res, "size") else 0
            flag  = "  *** LARGE — possible embedded payload ***" if rsize > 50_000 else ""
            lines.append(f"  {rname}  ({rsize:,} bytes){flag}")
            if rsize > 50_000:
                caps["embedded_resource_blob"].add(f"{rname} ({rsize:,} bytes)")
    except Exception as e:
        lines.append(f"  [error: {e}]")

    lines.append("\n== Obfuscation Indicators ==")
    if total_types > 0:
        ratio = obf_count / total_types
        lines.append(f"  Obfuscated-looking type names: {obf_count}/{total_types} ({ratio:.0%})")
        if ratio > 0.3:
            caps["obfuscation"].add(f"{ratio:.0%} of type names appear obfuscated")

    lines.append("\n== Capability Summary ==")
    if caps:
        for cap, refs in sorted(caps.items()):
            lines.append(f"  {cap}: {', '.join(sorted(refs)[:4])}")
    else:
        lines.append("  No suspicious capabilities detected.")

    return {
        "ok": True,
        "stdout": "\n".join(lines),
        "stderr": "",
        "rc": 0,
        "capabilities": {k: list(v) for k, v in caps.items()},
    }


def binwalk_scan(path: str) -> Dict[str, Any]:
    """
    Scan a binary for embedded file signatures using binwalk.
    Finds payloads hidden inside PE overlays, appended archives, certificate
    blobs, or any embedded content that pefile's overlay method misses.
    Runs on PE and ELF files in preflight — does not extract, only reports.
    """
    if not which("binwalk"):
        return {"ok": False, "error": "binwalk not installed", "stdout": "", "stderr": "", "rc": 1}
    return run_jailed(["binwalk", path], path, timeout=60, max_bytes=100000)


@tool
def readpe_all(path: str) -> Dict[str, Any]:
    if which("readpe"):
        return run(["readpe", "--all", path], timeout=45)
    return {"ok": False, "error": "readpe not installed"}

@tool
def pesec(path: str) -> Dict[str, Any]:
    if which("pesec"):
        return run(["pesec", path], timeout=30, max_bytes=220000)
    return {"ok": False, "error": "pesec not installed"}

@tool
def objdump_pe_headers(path: str) -> Dict[str, Any]:
    # -x includes headers/sections/imports in many cases; bounded by MAX anyway
    return run_jailed(["objdump", "-x", path], path, timeout=60)

@tool
def objdump_pe_imports_dynamic(path: str) -> Dict[str, Any]:
    # Often useful to spot suspicious imports and delay-load; also small-ish
    # (On some PEs, -p may fail; that's okay.)
    return run_jailed(["objdump", "-p", path], path, timeout=60)

@tool
def radare2_quick_json(path: str) -> Dict[str, Any]:
    if which("r2"):
        # iIj = binary info JSON, iij = imports JSON.
        # No -A flag: full analysis (aaa) is very slow on complex PE/ELF and not
        # needed just to list imports/info. -2 suppresses stderr noise.
        cmds = "e scr.color=false;iIj;iij"
        return run_jailed(["r2", "-2", "-q", "-c", cmds, path], path, timeout=60, max_bytes=650000)
    return {"ok": False, "error": "radare2 not installed"}

@tool
def radare2_entry_disasm(path: str) -> Dict[str, Any]:
    if which("r2"):
        # Cap radare2's own analysis time then disassemble entry0.
        # 'af' (analyze function) is lighter than 'aa' (analyze all).
        cmds = "e scr.color=false;e anal.timeout=15;af @ entry0;pdf @ entry0"
        return run_jailed(["r2", "-2", "-q", "-c", cmds, path], path, timeout=45, max_bytes=450000)
    return {"ok": False, "error": "radare2 not installed"}

@tool
def pe_overlay_info(path: str) -> Dict[str, Any]:
    try:
        pe = pefile.PE(path, fast_load=False)
        off = pe.get_overlay_data_start_offset()
        if off is None:
            return {"ok": True, "has_overlay": False}
        size = max(0, Path(path).stat().st_size - off)
        return {"ok": True, "has_overlay": size > 0, "overlay_offset": off, "overlay_size": size}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

@tool
def pe_imphash(path: str) -> Dict[str, Any]:
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        return {"ok": True, "imphash": pe.get_imphash()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@tool
def pe_meta_structured(path: str) -> Dict[str, Any]:
    """Extract structured PE metadata: compile timestamp, version strings, file size, signed status,
    and whether the binary was built with /Brepro (reproducible builds — timestamp is a content hash,
    not a real date). Detected via IMAGE_DEBUG_TYPE_REPRO (type 0x10) in the debug directory."""
    import datetime
    IMAGE_DEBUG_TYPE_REPRO = 0x10
    try:
        pe = pefile.PE(path, fast_load=False)
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_dt = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except (OSError, OverflowError, ValueError):
            compile_dt = None

        # Detect /Brepro: presence of IMAGE_DEBUG_TYPE_REPRO (0x10) debug entry means
        # the TimeDateStamp field contains a content hash, NOT a real compile time.
        # Microsoft uses this for reproducible Windows builds since VS2017.
        has_repro_debug = False
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for dbg in (pe.DIRECTORY_ENTRY_DEBUG or []):
                if dbg.struct.Type == IMAGE_DEBUG_TYPE_REPRO:
                    has_repro_debug = True
                    break

        version_info: Dict[str, str] = {}
        if hasattr(pe, "VS_VERSIONINFO"):
            for entry in (pe.VS_VERSIONINFO or []):
                if hasattr(entry, "StringFileInfo"):
                    for sfi in (entry.StringFileInfo or []):
                        for st in (sfi.StringTable or []):
                            for k, v in (st.entries or {}).items():
                                try:
                                    version_info[k.decode(errors="replace")] = v.decode(errors="replace")
                                except Exception:
                                    pass

        file_size = Path(path).stat().st_size

        # Reuse authenticode_verify which handles AIA cert fetching automatically.
        _av = authenticode_verify(path)
        _av_status = _av.get("status", "")
        if _av_status in ("SIGNATURE_VERIFIED", "SIGNATURE_VERIFIED_WITH_AIA_CERTS"):
            signed = True
        elif _av_status == "UNSIGNED":
            signed = False
        elif _av_status in ("SIGNATURE_PRESENT_DIGEST_OK_CHAIN_UNVERIFIABLE",):
            signed = None  # signature present and digest intact, chain unverifiable
        elif _av_status == "SIGNATURE_DIGEST_MISMATCH":
            signed = False  # file tampered
        else:
            signed = None  # unknown / tool missing

        signer_info = _extract_signer_info(path)

        return {
            "ok": True,
            "compile_timestamp": ts,
            "compile_datetime": compile_dt,
            "has_repro_debug": has_repro_debug,
            "version_info": version_info,
            "file_size": file_size,
            "signed": signed,
            "signer_info": signer_info,
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ---------------- ELF (more low-level visibility) ----------------

@tool
def readelf_all(path: str) -> Dict[str, Any]:
    return run_jailed(["readelf", "-a", path], path, timeout=60)

@tool
def objdump_elf_dynamic(path: str) -> Dict[str, Any]:
    # -p (program headers + dynamic section); good for DT_NEEDED/SONAME/RPATH/RUNPATH
    return run_jailed(["objdump", "-p", path], path, timeout=60, max_bytes=450000)

@tool
def ldd_deps(path: str) -> Dict[str, Any]:
    # Use readelf -d instead of ldd: extracts DT_NEEDED entries without executing
    # the binary (ldd runs the dynamic linker and can trigger malicious constructors)
    return run_jailed(["readelf", "-d", path], path, timeout=30, max_bytes=150000)

@tool
def objdump_elf_disasm(path: str) -> Dict[str, Any]:
    return run_jailed(["objdump", "-d", "-M", "intel", path], path, timeout=90)

# ---------------- OFFICE ----------------

@tool
def olevba_json(path: str) -> Dict[str, Any]:
    if which("olevba"):
        return run_jailed(["olevba", "--json", "--reveal", "--decode", path], path, timeout=150, max_bytes=650000)
    return {"ok": False, "error": "olevba not installed"}

@tool
def oledump_list(path: str) -> Dict[str, Any]:
    oledump = TOOLS_DIR / "oledump.py"
    if oledump.exists():
        return run_jailed(["python3", str(oledump), "-i", path], path, timeout=120, max_bytes=650000)
    return {"ok": False, "error": f"oledump.py not found at {oledump}"}

@tool
def oleobj_extract(path: str) -> Dict[str, Any]:
    if which("oleobj"):
        outdir = EXTRACT_DIR / "oleobj"
        _safe_mkdir(outdir)
        before = {f for f in outdir.rglob("*") if f.is_file()} if outdir.exists() else set()
        result = run(["oleobj", "-d", str(outdir), path], timeout=180, max_bytes=650000)
        after = {f for f in outdir.rglob("*") if f.is_file()} if outdir.exists() else set()
        new_files = sorted(after - before)
        if new_files:
            result["extracted_files"] = [str(f) for f in new_files]
        return result
    return {"ok": False, "error": "oleobj not installed (oletools)"}


@tool
def oledump_details(path: str) -> Dict[str,Any]:
    ole2 = TOOLS_DIR / "olemagic.sh"
    if ole2.exists():
        return run_jailed([str(ole2), path], path, timeout=60, max_bytes=650000)
    return {"ok": False,"error": f"olemagic.sh not found at {ole2}"}

def _rtfobj_parse_packages(stdout: str) -> Dict[str, str]:
    """Parse rtfobj stdout to map hex offset → OLE Package original filename.
    Returns dict like {"000AF79F": "license.js"}.
    """
    import re as _re
    mapping: Dict[str, str] = {}
    current_offset: str | None = None
    for line in stdout.splitlines():
        m = _re.search(r"\|([0-9A-Fa-f]+)h\s*\|", line)
        if m:
            current_offset = m.group(1).upper().zfill(8)
        if current_offset and "Filename:" in line:
            fn_m = _re.search(r"Filename:\s*'([^']+)'", line)
            if fn_m:
                mapping[current_offset] = fn_m.group(1)
    return mapping

@tool
def rtfobj_extract(path: str) -> Dict[str, Any]:
    if which("rtfobj"):
        outdir = EXTRACT_DIR / "rtfobj"
        _safe_mkdir(outdir)
        # Recursive scan before — rtfobj may write to subdirs
        before = {f for f in outdir.rglob("*") if f.is_file()} if outdir.exists() else set()
        # Use run() not run_jailed(): firejail whitelist blocks writes to extracted dir.
        # rtfobj is a Python analysis tool (oletools) — it parses structure, does not execute code.
        # -s all is REQUIRED: -d alone only sets dest dir, files are not saved without -s.
        result = run(["rtfobj", "-d", str(outdir), "-s", "all", path], timeout=180, max_bytes=650000)
        after = {f for f in outdir.rglob("*") if f.is_file()} if outdir.exists() else set()
        new_files = sorted(after - before)

        if new_files:
            # Try to rename rtf-object-XXXXXXXX.bin → original filename from OLE Package metadata
            pkg_map = _rtfobj_parse_packages(result.get("stdout") or "")
            renamed: list[str] = []
            for f in new_files:
                m = __import__("re").search(r"rtf-object-([0-9A-Fa-f]+)", f.name)
                if m:
                    offset = m.group(1).upper().zfill(8)
                    orig_name = pkg_map.get(offset)
                    if orig_name:
                        dest = f.parent / orig_name
                        try:
                            f.rename(dest)
                            renamed.append(str(dest))
                        except Exception:
                            renamed.append(str(f))
                    else:
                        renamed.append(str(f))
                else:
                    renamed.append(str(f))
            result["extracted_files"] = renamed
            result["stdout"] = (result.get("stdout") or "") + (
                "\n\n[Extracted files saved to disk — use exact paths below with 'path' field:]\n"
                + "\n".join(renamed)
            )
        else:
            result["stdout"] = (result.get("stdout") or "") + (
                "\n\n[No files were written to disk by rtfobj. "
                "OLE object data is described above but not extractable to disk in this run.]"
            )
        return result
    return {"ok": False, "error": "rtfobj not installed (oletools)"}

@tool
def openxml_list(path: str) -> Dict[str, Any]:
    if which("zipinfo"):
        return run_jailed(["zipinfo", "-1", path], path, timeout=30, max_bytes=300000)
    return {"ok": False, "error": "zipinfo not installed"}

@tool
def openxml_extract(path: str) -> Dict[str, Any]:
    if which("unzip"):
        outdir = EXTRACT_DIR / "openxml"
        _safe_mkdir(outdir)
        before = {f for f in outdir.rglob("*") if f.is_file()} if outdir.exists() else set()
        result = run(["unzip", "-j", "-o", path, "-d", str(outdir)], timeout=180, max_bytes=200000)
        after = {f for f in outdir.rglob("*") if f.is_file()} if outdir.exists() else set()
        new_files = sorted(after - before)
        if new_files:
            result["extracted_files"] = [str(f) for f in new_files]
        return result
    return {"ok": False, "error": "unzip not installed"}


# ---------------- SCRIPT HELPERS ----------------

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])")

def _extract_base64_blobs(text: str, outdir: Path, limit: int = 5):
    found = []
    for i, m in enumerate(_B64_RE.finditer(text)):
        if i >= limit:
            break
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "===")
            if len(raw) < 128:
                continue
            h = _sha256_bytes(raw)
            out = outdir / f"b64_{i}_{h[:12]}.bin"
            out.write_bytes(raw)
            found.append({"file": str(out), "sha256": h, "size": len(raw), "type": "base64_blob"})
        except Exception:
            continue
    return found

@tool
def script_content(path: str) -> Dict[str, Any]:
    """Return file content for analysis. Auto-detects text vs binary:
    text files → cat; binary files → strings (printable ASCII extraction)."""
    p = Path(path)
    try:
        sample = p.read_bytes()[:4096]
    except Exception as e:
        return {"ok": False, "error": str(e)}
    null_count = sample.count(b"\x00")
    non_printable = sum(1 for b in sample if b < 0x09 or (0x0e <= b <= 0x1f and b != 0x1b))
    is_binary = null_count > 0 or non_printable > len(sample) * 0.1
    if is_binary:
        # Binary file — extract printable strings instead of dumping raw bytes
        if which("strings"):
            result = run(["strings", "-n", "8", path], timeout=30, max_bytes=650000)
        else:
            result = run(["strings", path], timeout=30, max_bytes=650000)
        result["note"] = "Binary file detected — showing extracted strings, not raw content"
        return result
    return run(["cat", path], timeout=20, max_bytes=650000)

@tool
def shell_lint(path: str) -> Dict[str, Any]:
    """bash -n syntax check — only meaningful for sh/bash scripts (skipped for Perl, Python, PHP, ...)."""
    try:
        with open(path, "rb") as fh:
            first = fh.readline(300).lower()
    except OSError as e:
        return {"ok": False, "error": str(e)}
    m = re.match(rb"#!\s*(?:/usr)?(?:/local)?/bin/(?:env\s+)?([\w.-]+)", first)
    interp = m.group(1).decode() if m else ""
    ext = Path(path).suffix.lower()
    if (interp and interp not in ("sh", "bash", "dash", "ash", "ksh", "zsh")) or \
            (not interp and ext not in ("", ".sh", ".bash", ".ksh", ".zsh")):
        return {"ok": True, "stdout": f"skipped: not a POSIX shell script ({interp or ext}); bash -n does not apply",
                "rc": 0}
    return run(["bash", "-n", path], timeout=10, max_bytes=100000)

@tool
def js_beautify(path: str) -> Dict[str, Any]:
    if which("js-beautify"):
        return run(["js-beautify", path], timeout=40, max_bytes=650000)
    return {"ok": False, "error": "js-beautify not installed"}

# ---------------- EMBEDDED PAYLOAD EXTRACTION ----------------

@tool
def extract_payloads(path: str) -> Dict[str, Any]:
    p = Path(path)
    info = file_info(path)
    kind = guess_kind_from_fileinfo(info.get("stdout", ""), path)

    outdir = EXTRACT_DIR / f"{p.name}_{int(p.stat().st_mtime)}"
    _safe_mkdir(outdir)

    extracted = []
    notes = []

    if kind == "pe":
        try:
            pe = pefile.PE(path, fast_load=False)
            off = pe.get_overlay_data_start_offset()
            if off is not None:
                overlay = p.read_bytes()[off:]
                if overlay:
                    h = _sha256_bytes(overlay)
                    out = outdir / f"pe_overlay_{h[:12]}.bin"
                    out.write_bytes(overlay)
                    extracted.append({"file": str(out), "sha256": h, "size": len(overlay), "type": "pe_overlay"})
        except Exception as e:
            notes.append(f"PE overlay extraction failed: {type(e).__name__}: {e}")

    if kind in ["office"]:
        if which("oleobj"):
            run(["oleobj", "-d", str(outdir), path], timeout=180, max_bytes=200000)
        if which("rtfobj"):
            run(["rtfobj", "-d", str(outdir), path], timeout=180, max_bytes=200000)

    if kind == "office_openxml":
        if which("unzip"):
            run(["unzip", "-j", "-o", "-q", path, "-d", str(outdir)], timeout=180, max_bytes=200000)
            vba = list(outdir.rglob("vbaProject.bin"))
            if vba:
                notes.append(f"Found vbaProject.bin: {vba[0]}")

    if kind in ["ps1", "shell", "js"]:
        try:
            text = p.read_text(errors="replace")
            extracted.extend(_extract_base64_blobs(text, outdir, limit=8))
        except Exception as e:
            notes.append(f"Script base64 extraction failed: {type(e).__name__}: {e}")

    # enumerate extracted files
    for f in outdir.rglob("*"):
        if f.is_file():
            try:
                sz = f.stat().st_size
                if sz == 0:
                    continue
                h = _sha256_file(f)
                extracted.append({"file": str(f), "sha256": h, "size": sz, "type": "extracted_file"})
            except Exception:
                continue

    # dedupe by path (prefer specific types over generic extracted_file)
    uniq = {}
    for e in extracted:
        f = e.get("file")
        if not f:
            continue
        if f not in uniq:
            uniq[f] = e
            continue
        prev = uniq[f]
        prev_t = str(prev.get("type", "") or "").lower()
        new_t  = str(e.get("type", "") or "").lower()
        # never overwrite a specific typed artifact with the generic "extracted_file"
        if prev_t != "extracted_file" and new_t == "extracted_file":
            continue
        # but do overwrite generic with specific
        if prev_t == "extracted_file" and new_t != "extracted_file":
            uniq[f] = e
            continue
        # otherwise keep the first
        # (stable results; avoids flip-flopping)
        continue
    extracted = list(uniq.values())

    return {
        "ok": True,
        "kind": kind,
        "output_dir": str(outdir),
        "extracted": extracted[:200],
        "notes": notes[:30],
    }

# ---------------- FLOSS ----------------

@tool
def floss_strings(path: str) -> Dict[str, Any]:
    """Run FLARE FLOSS to extract deobfuscated stack strings and encoded strings missed by 'strings'. Falls back to strings (ASCII + UTF-16LE) for non-PE formats."""
    if not which("floss"):
        return {"ok": False, "error": "floss not installed (pip install flare-floss)"}
    result = run_jailed(["floss", path], path, timeout=120, max_bytes=650000)
    stderr = result.get("stderr", "") or ""
    if result.get("rc", 0) != 0 and "FLOSS currently supports" in stderr:
        ascii_r = run_jailed(["strings", "-a", "-n", "5", path], path, timeout=60, max_bytes=300000)
        utf16_r = run_jailed(["strings", "-a", "-n", "5", "-e", "l", path], path, timeout=60, max_bytes=300000)
        combined = ""
        if ascii_r.get("stdout"):
            combined += "=== ASCII strings ===\n" + ascii_r["stdout"]
        if utf16_r.get("stdout"):
            combined += "\n=== UTF-16LE strings ===\n" + utf16_r["stdout"]
        return {
            "ok": True,
            "fallback": "strings",
            "stdout": combined[:650000],
            "stderr": f"FLOSS not supported for this format. Fell back to strings.\nFLOSS error: {stderr[:200]}",
            "rc": 0,
        }
    return result


# ---------------- PDF ----------------

@tool
def pdf_analysis(path: str) -> Dict[str, Any]:
    """Analyze PDF for suspicious keywords (/JS, /OpenAction, /Launch, /EmbeddedFile, etc.) and extract strings."""
    result: Dict[str, Any] = {"ok": True}

    # Binary keyword scan — works without any extra lib
    _suspicious = [b"/JS", b"/JavaScript", b"/AA", b"/OpenAction", b"/Launch",
                   b"/EmbeddedFile", b"/AcroForm", b"/XFA", b"/RichMedia",
                   b"/URI", b"/SubmitForm", b"/ImportData", b"/GoToR"]
    try:
        data = Path(path).read_bytes()
        result["keyword_hits"] = {
            kw.decode(): data.count(kw) for kw in _suspicious if data.count(kw) > 0
        }
        result["stream_count"] = data.count(b"stream")
        result["object_count"] = data.count(b" obj")
    except Exception as e:
        result["keyword_scan_error"] = str(e)

    # pdfid.py (Didier Stevens)
    pdfid = TOOLS_DIR / "pdfid.py"
    if pdfid.exists():
        result["pdfid"] = run_jailed(["python3", str(pdfid), path], path, timeout=60, max_bytes=200000)

    # pdf-parser.py stats
    pdfparser = TOOLS_DIR / "pdf-parser.py"
    if pdfparser.exists():
        result["pdf_parser_stats"] = run_jailed(
            ["python3", str(pdfparser), "--stats", path], path, timeout=60, max_bytes=200000
        )

    result["strings_preview"] = run_jailed(
        ["strings", "-a", "-n", "6", path], path, timeout=40, max_bytes=200000
    ).get("stdout", "")[:8000]

    # Build a unified stdout for downstream consumers (report, evidence pack, LLM)
    lines = []
    if result.get("keyword_hits"):
        lines.append("=== Suspicious keyword hits ===")
        for kw, count in result["keyword_hits"].items():
            lines.append(f"  {kw}: {count}")
    lines.append(f"stream_count: {result.get('stream_count', 0)}")
    lines.append(f"object_count: {result.get('object_count', 0)}")
    if result.get("pdfid", {}).get("stdout"):
        lines.append("\n=== pdfid ===")
        lines.append(result["pdfid"]["stdout"][:3000])
    if result.get("pdf_parser_stats", {}).get("stdout"):
        lines.append("\n=== pdf-parser stats ===")
        lines.append(result["pdf_parser_stats"]["stdout"][:3000])
    if result.get("strings_preview"):
        lines.append("\n=== strings preview ===")
        lines.append(result["strings_preview"][:2000])
    result["stdout"] = "\n".join(lines)

    return result


# ---------------- LNK ----------------

@tool
def lnk_analysis(path: str) -> Dict[str, Any]:
    """Parse Windows LNK shortcut: extract target path, arguments, working dir, metadata."""
    import json as _json
    from datetime import datetime as _dt
    class _DTEncoder(_json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, _dt):
                return obj.isoformat()
            return super().default(obj)
    try:
        import LnkParse3
        with open(path, "rb") as fh:
            lnk = LnkParse3.lnk_file(fh)
        info = lnk.get_json()
        # Round-trip through JSON to convert all datetime objects to strings
        # so the returned dict is always JSON-serializable downstream.
        info = _json.loads(_json.dumps(info, cls=_DTEncoder))
        stdout = _json.dumps(info, indent=2, ensure_ascii=False)[:8000]
        return {"ok": True, "lnk": info, "stdout": stdout}
    except ImportError:
        pass
    except Exception as e:
        return {"ok": False, "error": f"LnkParse3 error: {e}", "stdout": f"LnkParse3 error: {e}"}
    # Fallback: strings
    s = run_jailed(["strings", "-a", "-n", "4", path], path, timeout=30, max_bytes=50000)
    fb = s.get("stdout", "")[:3000]
    return {"ok": False, "error": "LnkParse3 not installed", "strings_fallback": fb, "stdout": fb}


@tool
def exiftool_lnk(path: str) -> Dict[str, Any]:
    """
    Run exiftool on a Windows LNK shortcut to extract structured metadata:
    target file, command-line arguments, working directory, icon location,
    hotkey, creation/modification timestamps, and volume info.
    Useful when lnk_analysis output is sparse or unavailable.
    """
    if not which("exiftool"):
        return {"ok": False, "error": "exiftool not installed (apt install libimage-exiftool-perl)", "stdout": ""}
    result = run_jailed(["exiftool", "-j", path], path, timeout=30, max_bytes=30000)
    # -j gives JSON; if it fails fall back to plain text
    if result.get("rc") != 0 or not (result.get("stdout") or "").strip():
        result = run_jailed(["exiftool", path], path, timeout=30, max_bytes=30000)
    return result


@tool
def lecmd_lnk(path: str) -> Dict[str, Any]:
    """
    Run LECmd (Eric Zimmerman's forensic LNK parser) on a Windows LNK shortcut.
    Provides the most complete LNK analysis: shell item IDs, volume serial numbers,
    machine identifier, tracker data, network share info, and full argument decoding.
    Requires LECmd.exe (set MALHAUS_LECMD_PATH) and mono on Linux.
    """
    lecmd = os.environ.get("MALHAUS_LECMD_PATH", "")
    if not lecmd:
        for candidate in ["/opt/lecmd/LECmd.exe", "/opt/LECmd/LECmd.exe",
                          "/tools/LECmd.exe", "/usr/local/share/lecmd/LECmd.exe"]:
            if os.path.exists(candidate):
                lecmd = candidate
                break
    if not lecmd:
        return {
            "ok": False,
            "error": "LECmd not found. Download from https://github.com/EricZimmerman/LECmd and set MALHAUS_LECMD_PATH=/path/to/LECmd.exe",
            "stdout": "",
        }
    # On Linux run under mono; on Windows call directly
    mono = which("mono")
    cmd = ([mono, lecmd] if mono else [lecmd]) + ["-f", path, "--csv", "-"]
    result = run_jailed(cmd, path, timeout=60, max_bytes=50000)
    # LECmd writes summary to stdout and errors to stderr
    if not (result.get("stdout") or "").strip() and (result.get("stderr") or "").strip():
        result["stdout"] = result["stderr"]
    return result


# ---------------- ARCHIVE (ZIP / 7z / RAR) ----------------

def _check_archive_uncompressed_size(path: str, max_bytes: int, password: str = "") -> Optional[str]:
    """
    Read archive metadata WITHOUT extracting and return an error string if the
    total uncompressed size exceeds max_bytes, or None if it is acceptable.

    For ZIP files Python's zipfile reads only the central directory (a few KB at
    the end of the file) — no decompression happens at all.
    For 7z/RAR/other formats we run `7z l -slt` which lists sizes without writing
    anything to disk.

    This stops decompression-bomb attacks (e.g. a 10 KB zip that expands to 10 GB)
    before a single byte of output is written.
    """
    import zipfile as _zf
    try:
        if _zf.is_zipfile(path):
            with _zf.ZipFile(path) as zf:
                entries = zf.infolist()
            # Encrypted entries without a password are already blocked above;
            # sizes in encrypted central directories could be spoofed, so skip
            # the bomb check if all entries are encrypted and no password given.
            if entries and all(bool(e.flag_bits & 0x1) for e in entries) and not password:
                return None
            total = sum(e.file_size for e in entries)
            if total > max_bytes:
                return (
                    f"archive bomb rejected: total uncompressed size "
                    f"{total / (1024 * 1024):.1f} MB exceeds "
                    f"{max_bytes / (1024 * 1024):.0f} MB limit"
                )
            return None
    except Exception:
        pass  # not a ZIP or unreadable — fall through to 7z listing

    # For RAR, 7z, and other formats: use `7z l -slt` to read metadata only.
    # Pass password so encrypted archives report real uncompressed sizes.
    try:
        _list_cmd = ["7z", "l", "-slt"]
        if password:
            _list_cmd.append(f"-p{password}")
        _list_cmd.append(path)
        list_result = run(_list_cmd, timeout=15, max_bytes=500000)
        stdout = list_result.get("stdout") or ""
        total = 0
        for line in stdout.splitlines():
            if line.startswith("Size = "):
                try:
                    total += int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
        if total > max_bytes:
            return (
                f"archive bomb rejected: total uncompressed size "
                f"{total / (1024 * 1024):.1f} MB exceeds "
                f"{max_bytes / (1024 * 1024):.0f} MB limit"
            )
    except Exception:
        pass  # listing failed — let the extraction attempt and rely on disk quota

    return None


def _archive_extract_impl(path: str, password: str = "", _depth: int = 0, _max_depth: int = 4) -> Dict[str, Any]:
    if not which("7z"):
        return {"ok": False, "error": "7z (p7zip-full) not installed"}

    import config as _cfg
    import zipfile as _zf

    # --- Pre-extraction encryption check (ZIP only) ---
    # For encrypted ZIPs without a password, 7z may:
    #   a) fail cleanly with rc=2 (AES-256) — caught later, or
    #   b) "succeed" producing garbage files (ZipCrypto empty password) — rc=0,
    #      wrong_password never set, and the rest of the pipeline analyses noise.
    # Detect this early via the ZIP central directory before touching the filesystem.
    if not password:
        try:
            if _zf.is_zipfile(path):
                with _zf.ZipFile(path) as _zobj:
                    _entries = _zobj.infolist()
                if _entries and any(bool(e.flag_bits & 0x1) for e in _entries):
                    return {
                        "ok": False,
                        "wrong_password": True,
                        "extract_rc": None,
                        "error": "Archive is encrypted — please resubmit and provide the password.",
                    }
        except Exception:
            pass  # not a ZIP or unreadable — continue to extraction

    max_bytes = getattr(_cfg, "MAX_UPLOAD_BYTES", 10 * 1024 * 1024)
    bomb_error = _check_archive_uncompressed_size(path, max_bytes, password=password)
    if bomb_error:
        return {"ok": False, "error": bomb_error}

    p = Path(path)
    outdir = EXTRACT_DIR / f"arc_{p.stem}_{int(p.stat().st_mtime)}"
    _safe_mkdir(outdir)

    cmd = ["7z", "x", f"-o{outdir}", "-y", "-bd"]
    if password:
        cmd.append(f"-p{password}")
    cmd.append(path)
    # Use run() not run_jailed(): firejail whitelist blocks writes to extracted dir.
    extract_result = run(cmd, timeout=120, max_bytes=200000)

    # Detect wrong/missing password: 7z returns rc=2 and leaves outdir empty
    extract_rc = extract_result.get("rc", 0)
    combined_out = (extract_result.get("stdout") or "") + (extract_result.get("stderr") or "")
    wrong_password = extract_rc != 0 and (
        "wrong password" in combined_out.lower()
        or "encrypted" in combined_out.lower()
        or not any(outdir.rglob("*"))
    )
    if wrong_password:
        return {
            "ok": False,
            "wrong_password": True,
            "extract_rc": extract_rc,
            "error": "Archive extraction failed — wrong or missing password.",
        }

    # Priority order for promotion: pe > elf > msi > office_openxml > office > script > pdf > lnk
    _PRIO = {"pe": 0, "elf": 1, "msi": 2, "office_openxml": 3, "office": 4,
             "ps1": 5, "vbs": 5, "hta": 5, "js": 5, "shell": 5,
             "pdf": 6, "lnk": 7}

    _EXT_KIND = {
        ".ps1": "ps1", ".vbs": "vbs", ".vbe": "vbs", ".hta": "hta",
        ".js": "js", ".bat": "shell", ".cmd": "shell", ".sh": "shell",
        ".msi": "msi", ".pdf": "pdf", ".lnk": "lnk",
        ".doc": "office", ".xls": "office", ".ppt": "office", ".rtf": "office",
        ".docm": "office", ".xlsm": "office", ".pptm": "office",
        ".docx": "office_openxml", ".xlsx": "office_openxml", ".pptx": "office_openxml",
        ".eml": "email", ".msg": "email",
        ".jsp": "shell", ".jspx": "shell", ".asp": "shell", ".aspx": "shell", ".php": "shell",
        ".txt": "shell",
    }

    # Magic bytes for extension-less files (e.g. VirusTotal samples)
    _MAGIC_KIND = [
        (b"MZ",                                   2, "pe"),
        (b"\x7fELF",                              4, "elf"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",   8, "office"),   # OLE2: Office/MSI
        (b"%PDF",                                  4, "pdf"),
        (b"\x4C\x00\x00\x00",                     4, "lnk"),      # Windows Shell Link
        (b"{\x5crtf",                              5, "office"),   # RTF
    ]

    all_files: list = []
    candidates: list = []   # (priority, size, path, kind)
    script_files: list = []

    for f in outdir.rglob("*"):
        if not f.is_file():
            continue
        try:
            sz = f.stat().st_size
            all_files.append({"path": str(f.relative_to(outdir)), "size": sz})
            with open(f, "rb") as fh:
                header = fh.read(1024)
            ext = f.suffix.lower()
            # For double-extension files (e.g. evil.jsp.txt), also check inner suffixes.
            # An attacker appends .txt to disguise a webshell — walk all suffixes left-to-right
            # so the most specific known type wins over the decoy outer extension.
            all_exts = [s.lower() for s in f.suffixes]
            for _e in all_exts:
                if _e in _EXT_KIND and _e != ".txt":
                    ext = _e
                    break

            # 1. Magic-byte detection first (works for extension-less files too)
            kind_f = None
            for magic_bytes, nbytes, mk in _MAGIC_KIND:
                if header[:nbytes] == magic_bytes:
                    # OLE2 could be MSI — prefer extension hint if available
                    if mk == "office" and ext == ".msi":
                        kind_f = "msi"
                    else:
                        kind_f = mk
                    break

            # 1b. Extension fallback BEFORE archive check — critical for OpenXML files:
            # .docx/.xlsx/.pptx are ZIP files (PK magic) but must be promoted as
            # office_openxml, not recursed into as nested archives.
            if kind_f is None and ext in _EXT_KIND:
                kind_f = _EXT_KIND[ext]

            # 1c. Other interpreted scripts: .cgi/.pl/.py/.rb..., or extension-less files with a
            # shebang / <?php / <% marker (binary-looking files are left to the archive check).
            if kind_f is None and b"\x00" not in header and not header.startswith((b"PK", b"Rar!", b"7z", b"\x1f\x8b")):
                all_script_exts = [e for e in all_exts if e in _SCRIPT_EXTS]
                kind_f = script_kind_from_header(header, all_script_exts[0] if all_script_exts else ext)

            # 2. Detect nested archives — only if we haven't identified the file yet.
            # This prevents OpenXML docs (ZIP-based) from being wrongly recursed into.
            _ARCHIVE_MAGIC = [
                (b"\x50\x4B\x03\x04", 4),           # ZIP
                (b"\x52\x61\x72\x21\x1A\x07\x00", 7), # RAR5
                (b"\x52\x61\x72\x21\x1A\x07\x01", 7), # RAR4
                (b"\x37\x7A\xBC\xAF\x27\x1C", 6),    # 7z
                (b"\x1F\x8B", 2),                     # gzip
            ]
            _ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".tgz", ".tar"}
            is_nested_archive = (
                kind_f is None
                and (
                    any(header[:nb] == mb for mb, nb in _ARCHIVE_MAGIC)
                    or ext in _ARCHIVE_EXTS
                )
            )
            if is_nested_archive:
                if _depth < _max_depth:
                    sub = _archive_extract_impl(str(f), password=password,
                                                _depth=_depth + 1, _max_depth=_max_depth)
                    if sub.get("ok") and sub.get("promoted_file") and sub.get("promoted_kind"):
                        sub_prio = _PRIO.get(sub["promoted_kind"], 99)
                        candidates.append((sub_prio, sz, Path(sub["promoted_file"]), sub["promoted_kind"]))
                # Never promote the raw archive file itself
                continue

            # 3. Skip unrecognized files
            if kind_f is None:
                continue

            prio = _PRIO.get(kind_f, 99)
            candidates.append((prio, sz, f, kind_f))

            if kind_f in ("ps1", "vbs", "hta", "js", "shell"):
                script_files.append(f)
        except Exception:
            continue

    all_files.sort(key=lambda x: x["size"], reverse=True)
    # Sort: lower priority number first, then largest by size
    candidates.sort(key=lambda x: (x[0], -x[1]))

    promoted_path = str(candidates[0][2]) if candidates else None
    promoted_kind = candidates[0][3] if candidates else None

    # Legacy field: largest_pe for backwards compat
    pe_candidates = [(sz, f) for (p, sz, f, k) in candidates if k == "pe"]
    pe_candidates.sort(reverse=True)
    largest_pe = str(pe_candidates[0][1]) if pe_candidates else None

    pe_strings = ""
    target_for_strings = largest_pe or promoted_path
    if target_for_strings:
        sr = run_jailed(["strings", "-a", "-n", "6", target_for_strings],
                        target_for_strings, timeout=40, max_bytes=200000)
        pe_strings = sr.get("stdout", "")[:10000]

    scripts: Dict[str, str] = {}
    for sf in script_files[:3]:
        try:
            scripts[sf.name] = sf.read_text(errors="replace")[:3000]
        except Exception:
            pass

    return {
        "ok": True,
        "extract_rc": extract_result.get("rc"),
        "password_used": bool(password),
        "nesting_depth": _depth,
        "extract_dir": str(outdir),
        "file_count": len(all_files),
        "files": all_files[:50],
        "pe_count": len(pe_candidates),
        "largest_pe": largest_pe,
        "promoted_file": promoted_path,
        "promoted_kind": promoted_kind,
        "pe_strings_preview": pe_strings,
        "script_files": scripts,
    }


@tool
def archive_extract(path: str) -> Dict[str, Any]:
    """Extract ZIP/7z/RAR archive and return file listing, largest PE strings, embedded scripts."""
    return _archive_extract_impl(path, password="")


@tool
def msi_extract(path: str) -> Dict[str, Any]:
    """
    Extract an MSI installer with 7z. Returns a structured inventory of all
    extracted files with PE detection and entropy hints for each, so the
    verdict LLM can use the path field to run targeted tools on any of them.
    """
    import math as _math
    from collections import Counter as _Counter

    def _quick_entropy(fpath: str) -> float:
        try:
            with open(fpath, "rb") as _f:
                data = _f.read(65536)  # sample first 64 KB
            if not data:
                return 0.0
            freq = _Counter(data)
            n = len(data)
            return -sum((c / n) * _math.log2(c / n) for c in freq.values())
        except Exception:
            return 0.0

    if not which("7z"):
        return {"ok": False, "error": "7z not installed"}

    p = Path(path)
    outdir = EXTRACT_DIR / f"msi_{p.stem}_{int(p.stat().st_mtime)}"
    _safe_mkdir(outdir)

    # Use run() not run_jailed(): firejail whitelist blocks writes to extracted dir.
    # 7z is an archive parser, not executing MSI content.
    extract_result = run(
        ["7z", "x", path, f"-o{outdir}", "-y", "-bd"],
        timeout=120, max_bytes=200000,
    )

    pe_files: list = []
    all_files: list = []
    for f in outdir.rglob("*"):
        if not f.is_file():
            continue
        try:
            sz = f.stat().st_size
            with open(f, "rb") as fh:
                magic = fh.read(4)
            is_pe = magic[:2] == b"MZ"
            is_elf = magic[:4] == b"\x7fELF"
            ent = _quick_entropy(str(f))
            entry = {
                "path": str(f),
                "name": f.name,
                "size": sz,
                "entropy": round(ent, 2),
                "type": "pe" if is_pe else ("elf" if is_elf else "other"),
            }
            all_files.append(entry)
            if is_pe or is_elf:
                pe_files.append(entry)
        except Exception:
            continue

    pe_files.sort(key=lambda x: x["size"], reverse=True)
    all_files.sort(key=lambda x: x["size"], reverse=True)
    largest_pe = pe_files[0]["path"] if pe_files else None

    # Strings preview of largest PE for backwards compat with strings_llm
    pe_strings = ""
    if largest_pe:
        s_res = run(["strings", "-a", "-n", "6", largest_pe], timeout=40, max_bytes=300000)
        pe_strings = s_res.get("stdout", "")

    # Build human-readable inventory for the LLM snip
    lines = []
    for e in all_files[:50]:
        flag = " *** HIGH ENTROPY ***" if e["entropy"] >= 7.0 else ""
        lines.append(f"  [{e['type']:5s}] {e['name']:40s}  {e['size']:>9,} B  entropy={e['entropy']}{flag}  path={e['path']}")
    inventory = "\n".join(lines)

    return {
        "ok": True,
        "extract_rc": extract_result.get("rc"),
        "extract_stderr": extract_result.get("stderr", "")[:1000],
        "extracted_files": all_files[:50],
        "pe_files": pe_files,
        "pe_count": len(pe_files),
        "largest_pe": largest_pe,
        "pe_strings_preview": pe_strings[:20000],
        "stdout": inventory,  # shown in report via show_block and in mandatory_snips
    }


# ---------------- BYTE HEATMAP (visualization, not an LLM tool) ----------------

def byte_heatmap(path: str) -> Dict[str, Any]:
    """
    Generate a byte heatmap of a file as a base64-encoded PNG (always 256x256).
    Samples the whole file evenly so large files still show full structure.
    Returns {"ok": True, "b64": "<base64 png>", "file_size": N}
    """
    try:
        import io, base64
        import numpy as np
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        with open(path, "rb") as f:
            data = np.frombuffer(f.read(), dtype=np.uint8)

        n = 256 * 256  # always 256×256
        if len(data) >= n:
            indices = np.linspace(0, len(data) - 1, n, dtype=int)
            sampled = data[indices]
        else:
            sampled = np.pad(data, (0, n - len(data)), "constant")

        matrix = sampled.reshape((256, 256))

        fig, ax = plt.subplots(figsize=(3, 3), dpi=85)
        fig.patch.set_facecolor("#07090c")
        ax.imshow(matrix, cmap="viridis", interpolation="nearest", aspect="equal")
        ax.axis("off")
        fig.tight_layout(pad=0)

        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight", pad_inches=0, facecolor="#07090c")
        plt.close(fig)
        buf.seek(0)
        return {"ok": True, "b64": base64.b64encode(buf.read()).decode("ascii"), "file_size": int(len(data))}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ─────────────────────────── JAR / Java ──────────────────────────────────────

@tool
def jar_manifest(path: str) -> Dict[str, Any]:
    """
    Extract META-INF/MANIFEST.MF from a JAR/WAR/EAR archive.
    Returns the Main-Class, Class-Path, permissions, and other manifest entries.
    Key indicators: Main-Class (entry point), unusual permissions, signed/unsigned.
    """
    result = run(["unzip", "-p", path, "META-INF/MANIFEST.MF"], timeout=30, max_bytes=65536)
    if not result.get("stdout", "").strip():
        # Try alternate manifest locations (WAR/EAR)
        result2 = run(["unzip", "-p", path, "WEB-INF/MANIFEST.MF"], timeout=15, max_bytes=65536)
        if result2.get("stdout", "").strip():
            return result2
        result["stdout"] = result.get("stdout", "") + "\n[No MANIFEST.MF found]"
    return result


@tool
def jarsigner_verify(path: str) -> Dict[str, Any]:
    """
    Verify JAR signature with jarsigner. Reports whether the JAR is signed,
    which certificates signed it, and whether the signature is valid or tampered.
    Unsigned JARs are common in malware; tampered signatures indicate injection.
    """
    return run(["jarsigner", "-verify", "-verbose", "-certs", path], timeout=60, max_bytes=200000)


@tool
def jar_class_list(path: str) -> Dict[str, Any]:
    """
    List all files inside a JAR/WAR/EAR archive with sizes.
    Shows .class files (Java bytecode), resources, embedded JARs, scripts,
    and native libraries (.so/.dll). Large .class files or nested JARs are suspicious.
    """
    return run(["unzip", "-l", path], timeout=30, max_bytes=200000)


@tool
def javap_disasm(path: str) -> Dict[str, Any]:
    """
    Disassemble Java .class files found inside a JAR using javap.
    Extracts the JAR, identifies the Main-Class from MANIFEST.MF and any other
    suspicious classes (names containing Payload, Loader, Dropper, Exploit, Agent,
    Inject, Shell, Backdoor, C2, Remote), then disassembles up to 5 classes.
    Shows bytecode instructions, method signatures, constant pool strings — reveals
    Runtime.exec(), socket connections, reflection, file I/O, and base64 decode calls.
    """
    import math as _math
    from collections import Counter as _Counter

    p = Path(path)
    outdir = EXTRACT_DIR / f"jar_{p.stem}_{abs(hash(path)) % 100000}"
    _safe_mkdir(outdir)

    # Extract JAR contents
    extract_result = run(["unzip", "-o", "-d", str(outdir), path], timeout=60, max_bytes=200000)
    if not extract_result.get("ok") and not list(outdir.rglob("*.class")):
        return {"ok": False, "error": "JAR extraction failed", "stdout": "", "stderr": extract_result.get("stderr", "")}

    # Parse Main-Class from MANIFEST.MF
    main_class = None
    manifest_path = outdir / "META-INF" / "MANIFEST.MF"
    if manifest_path.is_file():
        try:
            for line in manifest_path.read_text(errors="replace").splitlines():
                if line.startswith("Main-Class:"):
                    main_class = line.split(":", 1)[1].strip().replace(".", "/")
                    break
        except Exception:
            pass

    # Find all .class files
    all_classes = sorted(outdir.rglob("*.class"))
    if not all_classes:
        return {"ok": False, "error": "No .class files found in JAR", "stdout": extract_result.get("stdout", ""), "stderr": ""}

    # Prioritize: main class first, then suspicious names, then first few
    _SUSPICIOUS_PATTERNS = re.compile(
        r"(payload|loader|dropper|exploit|agent|inject|shell|backdoor|c2|remote|"
        r"stager|launcher|download|execute|runtime|reflect|obfusc|decode|decrypt|"
        r"install|persist|hook|bypass|elevat|priv|escalat)",
        re.IGNORECASE,
    )
    main_class_file = None
    if main_class:
        candidate = outdir / (main_class + ".class")
        if candidate.is_file():
            main_class_file = candidate

    suspicious = [f for f in all_classes if _SUSPICIOUS_PATTERNS.search(f.name) and f != main_class_file]
    rest = [f for f in all_classes if f != main_class_file and f not in suspicious]

    priority_list: list[Path] = []
    if main_class_file:
        priority_list.append(main_class_file)
    priority_list.extend(suspicious[:3])
    priority_list.extend(rest[: max(0, 5 - len(priority_list))])
    targets = priority_list[:5]

    # Disassemble each target class
    parts: list[str] = [
        f"Disassembled {len(targets)} of {len(all_classes)} classes "
        f"(main={main_class or 'unknown'}, suspicious={len(suspicious)}, total={len(all_classes)}):\n"
    ]
    for cls_file in targets:
        rel = cls_file.relative_to(outdir)
        parts.append(f"\n{'='*60}\n[{rel}]\n{'='*60}")
        result = run(["javap", "-c", "-p", "-verbose", str(cls_file)], timeout=30, max_bytes=40000)
        parts.append(result.get("stdout", "") or result.get("stderr", "") or "(no output)")

    combined = "\n".join(parts)
    return {
        "ok": True,
        "stdout": combined[:200000],
        "stderr": "",
        "rc": 0,
        "total_classes": len(all_classes),
        "main_class": main_class,
        "suspicious_class_count": len(suspicious),
        "disassembled": [str(t.relative_to(outdir)) for t in targets],
    }


@tool
def jar_extract_inner(path: str) -> Dict[str, Any]:
    """
    Extract a JAR/WAR/EAR and inventory all inner files with type, size, and entropy.
    Identifies embedded PE/ELF binaries, nested JARs, scripts (.js, .sh, .bat, .ps1),
    native libraries (.so, .dll), and configuration files.
    Use the 'path' field on follow-up tool calls to analyze any suspicious inner file.
    """
    import math as _math
    from collections import Counter as _Counter

    def _quick_entropy(fpath: str) -> float:
        try:
            with open(fpath, "rb") as _f:
                data = _f.read(65536)
            if not data:
                return 0.0
            freq = _Counter(data)
            n = len(data)
            return -sum((c / n) * _math.log2(c / n) for c in freq.values())
        except Exception:
            return 0.0

    p = Path(path)
    outdir = EXTRACT_DIR / f"jar_{p.stem}_{abs(hash(path)) % 100000}"
    _safe_mkdir(outdir)

    result = run(["unzip", "-o", "-d", str(outdir), path], timeout=60, max_bytes=200000)

    # Walk extracted files
    _PE_MAGIC = b"MZ"
    _ELF_MAGIC = b"\x7fELF"
    _INTERESTING_EXTS = {".jar", ".war", ".ear", ".js", ".sh", ".bat", ".ps1",
                         ".vbs", ".hta", ".py", ".rb", ".php", ".so", ".dll", ".exe"}

    files_info = []
    for f in sorted(outdir.rglob("*")):
        if not f.is_file():
            continue
        try:
            size = f.stat().st_size
            with open(f, "rb") as _fh:
                magic = _fh.read(4)
        except Exception:
            continue

        ftype = "other"
        if magic[:2] == _PE_MAGIC:
            ftype = "pe"
        elif magic[:4] == _ELF_MAGIC:
            ftype = "elf"
        elif f.suffix.lower() in _INTERESTING_EXTS:
            ftype = f.suffix.lower().lstrip(".")
        elif f.suffix.lower() == ".class":
            ftype = "class"

        entry = {
            "path": str(f),
            "name": f.name,
            "size": size,
            "type": ftype,
        }
        if ftype in ("pe", "elf") or (ftype not in ("class", "other") and size > 1024):
            entry["entropy"] = round(_quick_entropy(str(f)), 3)
        if ftype in ("pe", "elf", "jar", "war", "ear") or f.suffix.lower() in _INTERESTING_EXTS:
            files_info.append(entry)

    lines = [f"Extracted {outdir}:"]
    for fi in files_info:
        ent_str = f"  entropy={fi.get('entropy', '?')}" if "entropy" in fi else ""
        lines.append(f"  [{fi['type']:8}] {fi['name']:40}  {fi['size']:>10} bytes{ent_str}  path={fi['path']}")

    if not files_info:
        lines.append("  (no interesting files found — only .class and resources)")

    return {
        "ok": True,
        "stdout": "\n".join(lines),
        "stderr": "",
        "rc": 0,
        "extracted_files": files_info,
        "extract_dir": str(outdir),
    }


ALL_TOOLS = [
    # universal
    file_info, sha256, ssdeep_hash, entropy_shannon, strings_ascii, network_artifacts, extract_payloads, authenticode_verify,

    # documents / e-mail (phishing)
    email_parse, phishing_analysis,

    # installers
    installer_extract,

    # PE low-level
    upx_unpack, readpe_all, pesec, objdump_pe_headers, objdump_pe_imports_dynamic,
    radare2_quick_json, radare2_entry_disasm, pe_overlay_info, pe_imphash, pe_section_entropy,
    ghidra_malhaus,

    # ELF low-level
    readelf_all, objdump_elf_dynamic, ldd_deps, objdump_elf_disasm,

    # Office
    olevba_json, oledump_list, oledump_details, oleobj_extract, rtfobj_extract, openxml_list, openxml_extract,

    # scripts
    script_content, shell_lint, js_beautify,

    # MSI installer
    msi_extract,

    # deobfuscation
    floss_strings,

    # new file types
    pdf_analysis, lnk_analysis, exiftool_lnk, lecmd_lnk, archive_extract,

    # JAR / Java
    jar_manifest, jarsigner_verify, jar_class_list, javap_disasm, jar_extract_inner,
]


def detect_file_type(path: str) -> str:
    """Canonical file type detector used for DB + report consistency."""
    info = file_info(path)
    return guess_kind_from_fileinfo(info.get("stdout", ""), path)
