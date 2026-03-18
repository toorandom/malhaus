import re
from typing import Set

def extract_import_names_from_text(text: str) -> Set[str]:
    """
    Extract import-like symbol names from objdump/radare2 output.
    Not a malware keyword list; adapts to what the binary imports.
    """
    if not text:
        return set()

    names: Set[str] = set()

    # radare2 iMj often shows sym.imp.NAME
    for m in re.finditer(r"\bsym\.imp\.([A-Za-z_][A-Za-z0-9_@]{2,})\b", text):
        names.add(m.group(1))

    # Generic tokens that look like symbols, pruned
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_@]{3,})\b", text):
        tok = m.group(1)
        if "_" in tok or "@" in tok or (any(c.islower() for c in tok) and any(c.isupper() for c in tok)):
            if 4 <= len(tok) <= 64:
                names.add(tok)

    pruned = set()
    for n in names:
        if n.islower() and len(n) < 8:
            continue
        pruned.add(n)
    return pruned
