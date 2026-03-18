# ExportTriage.py
# @category Malhaus
# Exports a compact, high-signal JSON triage report to a path passed as the first arg.

import json, re

def safe(s, limit=400):
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\r"," ").replace("\n"," ")
    return s[:limit]

def main():
    # args: [output_path]
    try:
        out_path = getScriptArgs()[0]
    except:
        out_path = "triage.json"

    prog = currentProgram

    md = {
        "name": safe(prog.getName(), 260),
        "exe_path": safe(prog.getExecutablePath(), 500),
        "lang": safe(prog.getLanguageID()),
        "compiler_spec": safe(prog.getCompilerSpec().getCompilerSpecID()),
        "format": safe(prog.getExecutableFormat()),
        "image_base": safe(prog.getImageBase()),
        "entry": safe(prog.getEntryPoint()),
    }

    # External symbols (imports best-effort)
    ext = []
    symtab = prog.getSymbolTable()
    it = symtab.getExternalSymbols()
    count = 0
    while it.hasNext() and count < 3000:
        s = it.next()
        ext.append({
            "name": safe(s.getName(), 200),
            "address": safe(s.getAddress(), 80),
            "namespace": safe(s.getParentNamespace(), 200),
        })
        count += 1

    sus_re = re.compile(
        r"(VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|"
        r"LoadLibrary|GetProcAddress|WinExec|ShellExecute|URLDownloadToFile|"
        r"Internet(Open|Connect|Read|Write)|Http(Open|Send)|WSAStartup|connect|send|recv|"
        r"Reg(Set|Create|Open)|CreateProcess|Process32(First|Next)|"
        r"Crypt|BCrypt|RtlDecompressBuffer|Nt(Zw)?WriteVirtualMemory|Nt(Zw)?CreateThreadEx)",
        re.I
    )
    sus_imports = sorted({e["name"] for e in ext if sus_re.search(e["name"])})[:400]

    # High-signal strings only
    listing = prog.getListing()
    siter = listing.getDefinedData(True)
    hi = []
    url_re = re.compile(r"https?://", re.I)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    cmd_re = re.compile(r"(powershell|cmd\.exe|rundll32|reg\.exe|wscript|cscript|schtasks|mshta)", re.I)

    scount = 0
    while siter.hasNext() and scount < 200000:
        d = siter.next()
        dt = d.getDataType()
        if dt and dt.getName() == "string":
            val = d.getValue()
            st = safe(val, 500)
            if len(st) >= 6 and (url_re.search(st) or ip_re.search(st) or cmd_re.search(st)):
                hi.append(st)
                if len(hi) >= 250:
                    break
        scount += 1

    # Functions: take top by size
    fm = prog.getFunctionManager()
    funcs = []
    fiter = fm.getFunctions(True)
    while fiter.hasNext() and len(funcs) < 3000:
        f = fiter.next()
        body = f.getBody()
        funcs.append({
            "name": safe(f.getName(), 200),
            "entry": safe(f.getEntryPoint(), 80),
            "size": int(body.getNumAddresses()),
            "is_thunk": bool(f.isThunk()),
        })

    funcs_sorted = sorted(funcs, key=lambda x: x["size"], reverse=True)
    top_funcs = funcs_sorted[:50]

    out = {
        "meta": md,
        "imports_total": len(ext),
        "suspicious_imports": sus_imports,
        "interesting_strings": hi,
        "top_functions": top_funcs,
    }

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

main()
