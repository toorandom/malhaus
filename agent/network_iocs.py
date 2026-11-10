"""
Static network-artifact extraction (no execution).

Scans the whole sample — ASCII strings, UTF-16LE strings (Delphi/.NET/Win32
literals live there), FLOSS-decoded strings and kind-specific decoded text —
for URLs, domains, IPv4 addresses and e-mails, then validates them so that
code identifiers like `System.SysUtils` or `kernel32.dll` are not reported
as domains.

Each artifact keeps where it was seen and one context line, and well-known
PKI / schema / vendor hosts are flagged `benign_infra` so heuristics and the
report can separate them from candidate C2 infrastructure.
"""
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Set, Tuple

# Real TLDs: every ISO-3166 ccTLD plus the generic TLDs seen in practice.
_CC_TLDS = set("""
ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk
fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir
is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk
ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl
pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc
td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
""".split())
_G_TLDS = set("""
com net org edu gov mil int info biz name pro mobi asia tel travel aero coop museum jobs cat post xxx
app dev page cloud online site website space store shop tech top xyz club live life world today news
link click download win bid loan men work party trade date racing review stream science accountant
cricket faith gdn kim country webcam icu buzz fun host press services support solutions digital email
network systems center group company agency media network one vip ltd llc inc global tokyo moscow
berlin london nyc paris io ai gg ly to me tv cc ws su onion bit zip mov lol monster rest cyou sbs cfd
best bond quest beauty hair skin makeup boats yachts homes autos motorcycles pics surf mom rip ink pw
""".split())
VALID_TLDS = _CC_TLDS | _G_TLDS

# TLDs that collide with file extensions / code: only trusted when the host
# came from a URL or e-mail, never from a bare `name.ext` string.
_AMBIGUOUS_TLDS = {"py", "pl", "sh", "rs", "md", "cc", "ps", "so", "zip", "mov", "do", "in",
                   "is", "it", "to", "me", "as", "at", "id", "no", "am", "be", "go", "st",
                   "tv", "ms", "mk", "cs", "vb", "js", "jar", "bat", "cmd", "com"}

# Hosts that are routinely embedded by signing, manifests, installers or
# runtimes. Kept in the output (transparency) but flagged benign_infra.
_BENIGN_INFRA_SUFFIXES = (
    "digicert.com", "verisign.com", "symantec.com", "symcb.com", "symcd.com", "thawte.com",
    "geotrust.com", "sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "globalsign.com",
    "globalsign.net", "godaddy.com", "starfieldtech.com", "entrust.net", "letsencrypt.org",
    "identrust.com", "certum.pl", "ssl.com", "amazontrust.com", "pki.goog",
    "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "w3.org", "xmlsoap.org", "openxmlformats.org", "purl.org", "ns.adobe.com", "apache.org",
    "jrsoftware.org", "embarcadero.com", "borland.com", "gnu.org", "openssl.org", "mozilla.org",
    "nsis.sf.net", "nsis.sourceforge.io", "oracle.com", "java.com", "sun.com", "eclipse.org",
    "schemas.android.com", "unicode.org", "python.org", "qt.io", "example.com", "example.org", "example.net",
)

# Hosts that are benign brands but commonly abused for payload hosting / C2.
_ABUSED_SERVICE_SUFFIXES = (
    "pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "raw.githubusercontent.com",
    "gist.githubusercontent.com", "discord.com", "discordapp.com", "cdn.discordapp.com",
    "api.telegram.org", "t.me", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
    "no-ip.com", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "dropbox.com",
    "dropboxusercontent.com", "drive.google.com", "docs.google.com", "mega.nz", "anonfiles.com",
    "file.io", "temp.sh", "ipify.org", "ip-api.com", "ipinfo.io", "icanhazip.com", "checkip.amazonaws.com",
    "webhook.site", "firebaseio.com", "workers.dev", "pages.dev", "glitch.me", "000webhostapp.com",
    # shared hosting platforms — also why their registration age says nothing about the actor
    "github.io", "gitlab.io", "githubusercontent.com", "netlify.app", "vercel.app", "herokuapp.com",
    "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net", "cloudfront.net",
    "amazonaws.com", "appspot.com", "web.app", "firebaseapp.com", "blogspot.com", "wordpress.com",
    "weebly.com", "wixsite.com", "r2.dev", "onrender.com", "fly.dev", "replit.app", "surge.sh",
)

# No leading \b: DER-encoded certs glue a length byte in front (e.g. "Qhttp://...").
RE_URL = re.compile(r"(?i)(?:https?|ftp|wss?|tcp|udp)://[^\s\"'<>\\^`{|}]{3,}")
RE_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
RE_DOMAIN = re.compile(r"(?<![A-Za-z0-9_.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9_-])")
# Reject dotted-quads that are part of longer dotted numbers (version strings).
RE_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.]*\d)(?::(\d{1,5}))?")

# Network-capable imports (PE + ELF), grouped by capability.
NETWORK_APIS: Dict[str, Set[str]] = {
    "http_client": {"InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
                    "InternetConnectA", "InternetConnectW", "HttpOpenRequestA", "HttpOpenRequestW",
                    "HttpSendRequestA", "HttpSendRequestW", "InternetReadFile", "WinHttpOpen",
                    "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReadData",
                    "curl_easy_init", "curl_easy_perform"},
    "download_to_file": {"URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA",
                         "URLDownloadToCacheFileW", "URLOpenBlockingStreamA", "URLOpenBlockingStreamW"},
    "raw_sockets": {"WSAStartup", "WSASocketA", "WSASocketW", "socket", "connect", "WSAConnect",
                    "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept"},
    "dns": {"gethostbyname", "getaddrinfo", "GetAddrInfoW", "DnsQuery_A", "DnsQuery_W", "DnsQueryEx",
            "res_query", "gethostbyname_r"},
    "ftp": {"FtpPutFileA", "FtpPutFileW", "FtpGetFileA", "FtpGetFileW", "FtpOpenFileA", "FtpOpenFileW"},
    "network_recon": {"GetAdaptersInfo", "GetAdaptersAddresses", "GetIpNetTable", "GetExtendedTcpTable",
                      "NetShareEnum", "NetServerEnum", "WNetEnumResourceA", "WNetEnumResourceW"},
}


def _trim_url(u: str) -> str:
    """Strip trailing punctuation and ASN.1 bytes glued on by DER-encoded certs
    (e.g. http://ocsp.digicert.com0A, .../CA.crl0S)."""
    u = u.rstrip(".,;:)]}'\"")
    m = re.match(r"(?i)^([a-z]+://)([^/:?#]+)(.*)$", u)
    if not m:
        return u
    scheme, host, rest = m.groups()
    if not rest:
        # host glued to garbage: shorten until the last label is a real TLD
        for cut in range(0, 4):
            h = host[: len(host) - cut] if cut else host
            if "." in h and h.rsplit(".", 1)[1].lower() in VALID_TLDS:
                host = h
                break
    else:
        rest = re.sub(r"(?i)(\.(?:crl|crt|cer|p7c|htm|html|php|aspx?|jsp|exe|zip|txt))0.{0,2}$", r"\1", rest)
    return scheme + host + rest


def _host_of(url: str) -> str:
    m = re.match(r"(?i)^[a-z]+://(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)", url)
    return (m.group(1) if m else "").lower().strip("[]")


def is_plausible_domain(d: str, from_url: bool = False) -> bool:
    if len(d) > 253 or "." not in d:
        return False
    labels = d.split(".")
    tld = labels[-1]
    if tld.lower() not in VALID_TLDS:
        return False
    if any(not l or len(l) > 63 for l in labels):
        return False
    if from_url:
        return True
    # Code identifiers are mixed-case (System.IO, Vcl.Forms); hostnames in
    # binaries are almost always lowercase (or fully uppercase).
    if not (d.islower() or d.isupper()):
        return False
    if tld.lower() in _AMBIGUOUS_TLDS and len(labels) < 3:
        return False
    # Second-level label must look like a name, not a numeric/hex blob
    sld = labels[-2]
    if len(sld) < 2 or sld.isdigit():
        return False
    return True


def _ip_ok(ip: str, line: str, port: str = "") -> Tuple[bool, str]:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False, ""
    octs = [int(x) for x in ip.split(".")]
    if octs[1:] == [0, 0, 0] or ip in ("0.0.0.0", "255.255.255.255"):
        return False, ""
    # x.y.z.0 without a port is almost always a version number (2.1.0.0), not a host
    if octs[3] == 0 and not port:
        return False, ""
    if re.search(r"(?i)version|ver\b|v\d|assembly|fileversion|productversion|build", line):
        return False, ""
    if addr.is_loopback:
        return True, "loopback"
    if addr.is_private:
        return True, "private"
    if addr.is_multicast or addr.is_reserved or addr.is_link_local or addr.is_unspecified:
        return True, "reserved"
    return True, "public"


def _classify_host(host: str) -> str:
    h = host.lower()
    if any(h == s or h.endswith("." + s) for s in _BENIGN_INFRA_SUFFIXES):
        return "benign_infra"
    if any(h == s or h.endswith("." + s) for s in _ABUSED_SERVICE_SUFFIXES):
        return "abused_service"
    return "unknown"


def extract_network_artifacts(sources: Dict[str, str], import_names: Iterable[str] = ()) -> Dict[str, Any]:
    """
    sources: {source_name: text}. Returns
      {"urls": [...], "domains": [...], "ips": [...], "emails": [...],   # actionable only
       "items": [{"type","value","source","context","class"}],          # everything, with provenance
       "network_apis": {capability: [api,...]},
       "summary": "..."}
    """
    items: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(kind: str, value: str, source: str, line: str, cls: str) -> None:
        key = (kind, value.lower())
        if key in items:
            if source not in items[key]["sources"]:
                items[key]["sources"].append(source)
            return
        items[key] = {"type": kind, "value": value, "sources": [source],
                      "context": line[:200], "class": cls}

    for source, text in sources.items():
        if not text:
            continue
        for line in text.splitlines():
            if len(line) < 6 or "." not in line:
                continue
            url_hosts: Set[str] = set()
            for raw in RE_URL.findall(line):
                url = _trim_url(raw)
                host = _host_of(url)
                if not host:
                    continue
                try:
                    ipaddress.IPv4Address(host)
                    host_ok = True
                except ValueError:
                    host_ok = is_plausible_domain(host, from_url=True)
                if not host_ok:
                    continue
                url_hosts.add(host)
                add("url", url, source, line, _classify_host(host))
            for dom in RE_EMAIL.findall(line):
                if is_plausible_domain(dom, from_url=True):
                    m = re.search(r"(?i)[a-z0-9._%+-]+@" + re.escape(dom), line)
                    if m:
                        add("email", m.group(0), source, line, _classify_host(dom))
            for d in RE_DOMAIN.findall(line):
                dl = d.lower()
                if dl in url_hosts or is_plausible_domain(d):
                    add("domain", dl, source, line, _classify_host(dl))
            for ip, port in RE_IPV4.findall(line):
                ok, scope = _ip_ok(ip, line, port)
                if ok:
                    v = f"{ip}:{port}" if port else ip
                    add("ip", v, source, line, "unknown" if scope == "public" else scope)

    # hosts from URLs are domains too
    for (kind, _), it in list(items.items()):
        if kind == "url":
            h = _host_of(it["value"])
            try:
                ipaddress.IPv4Address(h)
                add("ip", h, it["sources"][0], it["context"], "unknown")
            except ValueError:
                add("domain", h, it["sources"][0], it["context"], it["class"])

    imports = set(import_names or ())
    network_apis = {cap: sorted(apis & imports) for cap, apis in NETWORK_APIS.items() if apis & imports}

    all_items = sorted(items.values(), key=lambda x: (x["class"] == "benign_infra", x["type"], x["value"]))
    actionable = [i for i in all_items if i["class"] not in ("benign_infra", "loopback", "reserved")]

    def vals(kind: str, pool: List[Dict[str, Any]]) -> List[str]:
        return [i["value"] for i in pool if i["type"] == kind][:200]

    out = {
        "urls": vals("url", actionable),
        "domains": vals("domain", actionable),
        "ips": [v for v in vals("ip", actionable)],
        "emails": vals("email", actionable),
        "benign_infra": sorted({_host_of(i["value"]) if i["type"] == "url" else i["value"]
                                for i in all_items if i["class"] == "benign_infra"})[:50],
        "abused_services": sorted({i["value"] for i in actionable if i["class"] == "abused_service"})[:50],
        "items": all_items[:300],
        "network_apis": network_apis,
        "sources_scanned": [s for s, t in sources.items() if t],
    }
    out["summary"] = summarize(out)
    return out


def summarize(na: Dict[str, Any], max_each: int = 5) -> str:
    """One human-readable line naming the actual artifacts (used in top_reasons)."""
    parts = []
    for key, label in (("urls", "URLs"), ("domains", "domains"), ("ips", "IPs"), ("emails", "e-mails")):
        v = na.get(key) or []
        if v:
            more = f" (+{len(v) - max_each} more)" if len(v) > max_each else ""
            parts.append(f"{label}: " + ", ".join(v[:max_each]) + more)
    apis = na.get("network_apis") or {}
    api_txt = ""
    if apis:
        api_txt = " Network-capable imports: " + "; ".join(
            f"{cap} ({', '.join(v[:4])})" for cap, v in apis.items())
    ages = []
    for a in na.get("domain_ages") or []:
        if a.get("age_days") is not None:
            tag = " NEWLY REGISTERED" if a["age_days"] < 30 else (" recent" if a["age_days"] < 180 else "")
            ages.append(f"{a['domain']} {a['age_days']}d old{tag}")
        elif a.get("status") == "not_registered":
            ages.append(f"{a['domain']} NOT REGISTERED")
    age_txt = (" Domain age: " + ", ".join(ages) + ".") if ages else ""
    benign = na.get("benign_infra") or []
    benign_txt = f" Ignored as benign infrastructure: {', '.join(benign[:6])}." if benign else ""
    if parts:
        return "Network artifacts found statically — " + "; ".join(parts) + "." + age_txt + api_txt + benign_txt
    return ("No actionable network artifacts (URLs/domains/IPs/e-mails) found in static strings"
            " — packed/encrypted payloads may still hide them." + api_txt + benign_txt)


# ---------------- domain age (RDAP / whois) ----------------

# Second-level labels under which registrations happen one level deeper (example.co.uk).
_SLD_REGISTRY = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic"}

_AGE_CACHE: Dict[str, Dict[str, Any]] = {}


def registrable_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_REGISTRY:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_RDAP_BOOTSTRAP: Dict[str, str] = {}
_RDAP_HEADERS = {"Accept": "application/rdap+json", "User-Agent": "malhaus-triage/1.0 (domain-age lookup)"}


def _rdap_base(tld: str, timeout: int) -> str:
    """Registry RDAP base URL for a TLD from the IANA bootstrap file (cached per process)."""
    import requests
    if not _RDAP_BOOTSTRAP:
        r = requests.get("https://data.iana.org/rdap/dns.json", timeout=timeout, headers=_RDAP_HEADERS)
        r.raise_for_status()
        for tlds, urls in r.json().get("services", []):
            for t in tlds:
                _RDAP_BOOTSTRAP[t.lower()] = urls[0].rstrip("/") + "/"
    return _RDAP_BOOTSTRAP.get(tld.lower(), "https://rdap.org/")


def _rdap_created(domain: str, timeout: int) -> Tuple[str, str]:
    import requests
    base = _rdap_base(domain.rsplit(".", 1)[-1], timeout)
    r = requests.get(f"{base}domain/{domain}", timeout=timeout, headers=_RDAP_HEADERS, allow_redirects=True)
    if r.status_code == 404:
        return "", "not_registered"
    r.raise_for_status()
    for ev in (r.json().get("events") or []):
        if (ev.get("eventAction") or "").lower() == "registration" and ev.get("eventDate"):
            return ev["eventDate"], "rdap"
    return "", "rdap_no_date"


def _whois_created(domain: str, timeout: int) -> Tuple[str, str]:
    import subprocess
    from shutil import which
    if not which("whois"):
        return "", "whois_unavailable"
    out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout).stdout
    m = re.search(r"(?im)^\s*(?:creation date|created(?: on)?|registered(?: on)?|registration time|domain registration date)\s*:\s*(.+)$", out)
    if m:
        return m.group(1).strip(), "whois"
    if re.search(r"(?i)no match|not found|no entries found|status:\s*free", out):
        return "", "not_registered"
    return "", "whois_no_date"


def _parse_date(s: str):
    from datetime import datetime, timezone
    s = s.split(" (")[0].strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d"):
        for cand in (s[:19], s.split()[0] if s else s):
            try:
                return datetime.strptime(cand, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def lookup_domain_ages(domains: Iterable[str], max_domains: int = 5, timeout: int = 6) -> List[Dict[str, Any]]:
    """Registration date / age in days for the registrable part of each domain.
    Network egress: only the domain name is sent (RDAP over HTTPS, whois fallback)."""
    from datetime import datetime, timezone
    out, seen = [], set()
    for host in domains:
        reg = registrable_domain(host)
        if reg in seen or "." not in reg:
            continue
        seen.add(reg)
        if len(seen) > max_domains:
            break
        if reg in _AGE_CACHE:
            out.append(dict(_AGE_CACHE[reg], host=host))
            continue
        created, via, err = "", "", ""
        try:
            created, via = _rdap_created(reg, timeout)
        except Exception as e:
            err = f"rdap: {type(e).__name__}"
        if not created and via != "not_registered":
            try:
                created, via = _whois_created(reg, timeout)
            except Exception as e:
                err = (err + f"; whois: {type(e).__name__}").strip("; ")
        rec: Dict[str, Any] = {"domain": reg, "created": created, "source": via, "age_days": None}
        d = _parse_date(created) if created else None
        if d:
            rec["created"] = d.date().isoformat()
            rec["age_days"] = (datetime.now(timezone.utc) - d).days
        if via == "not_registered":
            rec["status"] = "not_registered"
        if err and not d:
            rec["error"] = err
        _AGE_CACHE[reg] = rec
        out.append(dict(rec, host=host))
    return out
