"""
.NET PE static analysis tool using dnfile.

Extracts indicators that standard string analysis misses in .NET droppers:
- Type/assembly references (System.Management.Automation = PowerShell,
  System.Reflection = runtime code loading, etc.)
- .NET resource entries with sizes (large blobs = likely embedded payload)
- Suspicious method/type name patterns from the metadata tables
- Obfuscation indicators (high-entropy type/method names)
"""

import math
import re
from collections import defaultdict
from typing import Any, Dict

from langchain_core.tools import tool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# Type-reference namespaces that indicate specific capabilities
_SUSPICIOUS_NAMESPACES = {
    "System.Management.Automation":         "powershell_execution",
    "System.Management.Automation.Runspaces": "powershell_execution",
    "Microsoft.Win32":                       "registry_access",
    "Microsoft.Win32.TaskScheduler":         "scheduled_task",
    "System.Reflection":                     "runtime_code_loading",
    "System.Reflection.Emit":               "runtime_code_generation",
    "System.Runtime.InteropServices":        "native_interop",
    "System.Diagnostics.Process":           "process_creation",
    "System.Net":                            "network_access",
    "System.Net.Http":                       "network_access",
    "System.Net.Sockets":                    "raw_socket",
    "System.Security.Cryptography":          "crypto",
    "System.IO.Compression":                 "compression",
    "Microsoft.CSharp":                      "dynamic_code",
}

_SUSPICIOUS_TYPE_NAMES = {
    "Assembly":             "runtime_code_loading",
    "AssemblyLoad":         "runtime_code_loading",
    "Activator":            "runtime_code_loading",
    "DllImport":            "native_interop",
    "Marshal":              "native_interop",
    "WebClient":            "network_download",
    "HttpClient":           "network_access",
    "TcpClient":            "raw_socket",
    "UdpClient":            "raw_socket",
    "RegistryKey":          "registry_access",
    "Process":              "process_creation",
    "ProcessStartInfo":     "process_creation",
    "Mutex":                "mutex",
    "MemoryStream":         "memory_manipulation",
    "CryptoStream":         "crypto",
    "AesManaged":           "crypto",
    "RijndaelManaged":      "crypto",
    "RSACryptoServiceProvider": "crypto",
    "Deflate":              "compression",
    "GZipStream":           "compression",
    "Task":                 "threading",
    "Thread":               "threading",
    "Clipboard":            "clipboard_access",
    "Screen":               "screenshot",
    "Bitmap":               "screenshot",
    "SendKeys":             "input_simulation",
    "Microphone":           "audio_recording",
    "WaveIn":               "audio_recording",
    "PowerShell":           "powershell_execution",
    "Runspace":             "powershell_execution",
    "RunspaceFactory":      "powershell_execution",
    "WindowsIdentity":      "privilege_check",
    "WindowsPrincipal":     "privilege_check",
    "UACHelper":            "uac_bypass",
    "Impersonation":        "impersonation",
}

_OBFUSCATION_RE = re.compile(
    r'^[a-zA-Z0-9]{2,5}$|'          # very short names
    r'^[A-Z][a-z0-9]{0,2}[A-Z]|'   # mixed case without real words
    r'[^\x00-\x7f]'                  # non-ASCII
)

def _is_obfuscated_name(name: str) -> bool:
    """Heuristically detect obfuscated type/method names."""
    if not name or len(name) < 2:
        return False
    # High Shannon entropy for the name
    if _shannon(name) > 3.8 and len(name) >= 6:
        return True
    # All single letters or numbers-heavy
    if re.fullmatch(r'[a-zA-Z0-9]{1,4}', name):
        return True
    return False


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

@tool
def dotnet_analysis(path: str) -> Dict[str, Any]:
    """
    Analyse a .NET PE file with dnfile to extract metadata indicators.

    Reports type/assembly references (PowerShell, reflection, crypto, etc.),
    embedded .NET resources with sizes, and obfuscation indicators — all of
    which are invisible to regular strings analysis when the payload is
    encrypted or loaded at runtime via Assembly.Load.
    """
    try:
        import dnfile  # type: ignore
    except ImportError:
        return {"ok": False, "error": "dnfile not installed (pip install dnfile)"}

    try:
        dn = dnfile.dnPE(path)
    except Exception as e:
        return {"ok": False, "error": f"dnfile failed to parse: {e}"}

    if not dn.net:
        return {"ok": False, "error": "Not a .NET PE (no CLR header)"}

    lines = []
    capabilities: Dict[str, list] = defaultdict(list)
    obfuscated_count = 0
    total_type_names = 0

    # ── Assembly references ───────────────────────────────────────────────
    lines.append("== Assembly References ==")
    try:
        if dn.net.mdtables.AssemblyRef:
            for row in dn.net.mdtables.AssemblyRef:
                name = str(row.Name) if row.Name else ""
                ver = f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}"
                lines.append(f"  {name} v{ver}")
                for ns, cap in _SUSPICIOUS_NAMESPACES.items():
                    if name and ns.startswith(name):
                        capabilities[cap].append(f"AssemblyRef:{name}")
    except Exception as e:
        lines.append(f"  [error reading AssemblyRef: {e}]")

    # ── Type references ───────────────────────────────────────────────────
    lines.append("\n== Type References (suspicious) ==")
    seen_caps: Dict[str, set] = defaultdict(set)
    try:
        if dn.net.mdtables.TypeRef:
            for row in dn.net.mdtables.TypeRef:
                ns   = str(row.TypeNamespace) if row.TypeNamespace else ""
                name = str(row.TypeName) if row.TypeName else ""
                fqn  = f"{ns}.{name}" if ns else name
                total_type_names += 1

                if _is_obfuscated_name(name):
                    obfuscated_count += 1

                # Namespace match
                for sus_ns, cap in _SUSPICIOUS_NAMESPACES.items():
                    if ns.startswith(sus_ns) and fqn not in seen_caps[cap]:
                        capabilities[cap].add(fqn)
                        lines.append(f"  [{cap}] {fqn}")
                        seen_caps[cap].add(fqn)
                        break
                else:
                    # Type-name match
                    for sus_type, cap in _SUSPICIOUS_TYPE_NAMES.items():
                        if name == sus_type and fqn not in seen_caps[cap]:
                            capabilities[cap].add(fqn)
                            lines.append(f"  [{cap}] {fqn}")
                            seen_caps[cap].add(fqn)
                            break
    except Exception as e:
        lines.append(f"  [error reading TypeRef: {e}]")

    # ── Method references (look for Assembly.Load etc.) ───────────────────
    lines.append("\n== Suspicious Method References ==")
    _SUSPICIOUS_METHODS = {
        "Load":                 "runtime_code_loading",
        "LoadFile":             "runtime_code_loading",
        "LoadFrom":             "runtime_code_loading",
        "CreateInstance":       "runtime_code_loading",
        "InvokeMember":         "reflection_invoke",
        "GetMethod":            "reflection_invoke",
        "Invoke":               "reflection_invoke",
        "CreateProcess":        "process_creation",
        "VirtualAlloc":         "memory_injection",
        "VirtualAllocEx":       "memory_injection",
        "WriteProcessMemory":   "memory_injection",
        "CreateRemoteThread":   "thread_injection",
        "NtCreateThreadEx":     "thread_injection",
        "QueueUserAPC":         "apc_injection",
        "SetWindowsHookEx":     "hook_injection",
        "AddMpPreference":      "av_exclusion",
        "ExclusionPath":        "av_exclusion",
        "DisableRealtimeMonitoring": "av_disable",
    }
    try:
        if dn.net.mdtables.MemberRef:
            seen_methods: set = set()
            for row in dn.net.mdtables.MemberRef:
                mname = str(row.Name) if row.Name else ""
                for sus_m, cap in _SUSPICIOUS_METHODS.items():
                    if mname == sus_m and mname not in seen_methods:
                        capabilities[cap].add(f"MemberRef:{mname}")
                        lines.append(f"  [{cap}] {mname}()")
                        seen_methods.add(mname)
                        break
    except Exception as e:
        lines.append(f"  [error reading MemberRef: {e}]")

    # ── .NET resources ────────────────────────────────────────────────────
    lines.append("\n== .NET Resources ==")
    try:
        resources = dn.net.resources if dn.net.resources else []
        for res in resources:
            rname = str(res.name) if hasattr(res, "name") else "?"
            rsize = res.size if hasattr(res, "size") else 0
            flag  = " *** LARGE — possible embedded payload ***" if rsize > 50_000 else ""
            lines.append(f"  {rname}  ({rsize:,} bytes){flag}")
            if rsize > 50_000:
                capabilities["embedded_resource_blob"].add(f"{rname} ({rsize:,} bytes)")
    except Exception as e:
        lines.append(f"  [error reading resources: {e}]")

    # ── Obfuscation indicator ─────────────────────────────────────────────
    lines.append("\n== Obfuscation Indicators ==")
    if total_type_names > 0:
        ratio = obfuscated_count / total_type_names
        lines.append(f"  Obfuscated-looking type names: {obfuscated_count}/{total_type_names} ({ratio:.0%})")
        if ratio > 0.3:
            capabilities["obfuscation"].add(f"{ratio:.0%} of type names appear obfuscated")

    # ── Summary ───────────────────────────────────────────────────────────
    lines.append("\n== Capability Summary ==")
    if capabilities:
        for cap, refs in sorted(capabilities.items()):
            lines.append(f"  {cap}: {', '.join(sorted(refs)[:4])}")
    else:
        lines.append("  No suspicious capabilities detected.")

    return {
        "ok": True,
        "stdout": "\n".join(lines),
        "stderr": "",
        "rc": 0,
        "capabilities": {k: list(v) for k, v in capabilities.items()},
    }
