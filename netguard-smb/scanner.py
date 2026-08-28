import scapy.all as scapy
import socket
import ssl
import time
import re
import os
import json
import threading
import concurrent.futures
from dataclasses import dataclass, field, asdict

# ------------------------------------------------------------------
# MAC VENDOR LOOKUP (offline)
#
# Uses `manuf`, which ships Wireshark's OUI database as a local flat
# file -- no network call per host, no dependency on an external API
# this sandbox couldn't reach anyway (ieee.org / maclookup.app aren't
# in the egress allowlist). If the package isn't installed, lookups
# degrade to "Unknown" rather than crashing the scan.
# ------------------------------------------------------------------
try:
    from manuf import manuf
    _MAC_PARSER = manuf.MacParser()
    _VENDOR_LOOKUP_AVAILABLE = True
except ImportError:
    _MAC_PARSER = None
    _VENDOR_LOOKUP_AVAILABLE = False


def get_vendor(mac):
    """Resolve a MAC address's OUI to a manufacturer name. Returns 'Unknown' on any failure."""
    if not _VENDOR_LOOKUP_AVAILABLE:
        return "Unknown (install 'manuf' for vendor lookup)"
    try:
        vendor = _MAC_PARSER.get_manuf_long(mac)
        return vendor if vendor else "Unknown"
    except Exception:
        return "Unknown"

# ------------------------------------------------------------------
# scapy's default sockets are NOT thread-safe for concurrent sr1/sr()
# calls -- overlapping calls can cross-read each other's responses.
# We serialize all raw-packet operations (OS fingerprinting) behind
# this lock while leaving the pure-socket work (banner grabs) free
# to run fully concurrent in the thread pool.
# ------------------------------------------------------------------
SCAPY_LOCK = threading.Lock()


def validate_dns_service(ip, timeout=1.5, query_domain="example.com"):
    """
    A TCP connect() succeeding on port 53 only proves *something*
    completed a handshake -- it does not prove a real DNS resolver is
    listening. Many consumer routers transparently intercept/NAT
    port-53 TCP traffic to themselves for every LAN host (parental
    controls, ad-blocking DNS, etc.), which makes every device on the
    subnet falsely appear to run DNS.

    This sends an actual DNS query over UDP (the protocol DNS
    resolvers really speak) and checks for a well-formed response
    with a matching transaction ID. Plain UDP socket -- no raw socket,
    no elevated privileges required.

    Returns (is_valid: bool, detail: str).
    """
    try:
        query = scapy.DNS(rd=1, qd=scapy.DNSQR(qname=query_domain))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(bytes(query), (ip, 53))
            data, _ = sock.recvfrom(512)

        response = scapy.DNS(data)
        if response.id == query.id and response.qr == 1:
            return True, "confirmed: valid DNS response received over UDP"
        return False, "UDP response received but not a well-formed DNS answer"
    except socket.timeout:
        return False, "no UDP response -- likely TCP-only interception, not a real resolver"
    except Exception as e:
        return False, f"validation error: {type(e).__name__}: {e}"


# ------------------------------------------------------------------
# SECURITY RULES ENGINE
#
# Deliberately port/config-based, not vulnerability-based. A rule
# firing means "this is a commonly risky configuration, go look at
# it" -- it is NOT a claim that the host is exploitable. Precise
# vulnerability claims require a matched CVE against a confirmed
# service version + CPE string, which our current version detection
# can't reliably provide for the highest-risk services (SMB, RDP) --
# that's the gap the planned CVE/CVSS layer needs to close first,
# via real protocol-negotiation probes rather than banner grabs.
#
# `cve_ids` / `cvss_score` are present now as empty/None placeholders
# so that layer can populate them later without changing this
# engine's shape or the summary/report code that consumes it.
# ------------------------------------------------------------------

@dataclass
class Finding:
    id: str                   # stable identifier per rule, e.g. "NET-001" -- lets
                               # scan comparison track the same finding type across runs
    title: str                 # short human-readable summary, e.g. "SMB exposed"
    severity: str               # "high" | "medium" | "low" | "info"
    category: str                # "exposed_service" | "misconfiguration" | "vulnerability" | "informational"
                                  # -- tells the AI consumer what KIND of issue this is, since
                                  # an exposed service and a confirmed CVE shouldn't be handled
                                  # the same way even at matching severity
    confidence: str               # "confirmed" | "inferred" | "heuristic"
                                   # -- confirmed: we directly observed the condition (e.g. port
                                   #    connect succeeded). heuristic: derived from absence of
                                   #    evidence (e.g. no UDP response). Prevents the AI layer
                                   #    from treating a heuristic guess as a confirmed fact.
    port: int
    service: str
    description: str
    evidence: list             # list of short evidence strings backing this finding
    recommendation: str
    risk_score: float          # 0-10, hand-tuned per finding for now (see note below)
    mitre_technique: str = None                        # populated by future MITRE ATT&CK mapping
    cve_ids: list = field(default_factory=list)         # populated by future CVE lookup
    cvss_score: float = None                            # populated by future CVSS scoring


def rule_telnet_open(summary):
    if 23 in summary["open_ports"]:
        return [Finding(
            id="NET-001", title="Telnet exposed", severity="high",
            category="exposed_service", confidence="confirmed",
            port=23, service="Telnet",
            description="Telnet transmits credentials and all session data in cleartext.",
            evidence=["TCP port 23 open (connect scan)"],
            recommendation="Disable Telnet; use SSH for remote administration instead.",
            risk_score=7.5,
        )]
    return []


def rule_ftp_plaintext(summary):
    if 21 in summary["open_ports"]:
        return [Finding(
            id="NET-002", title="FTP exposed", severity="medium",
            category="exposed_service", confidence="confirmed",
            port=21, service="FTP",
            description="FTP transmits credentials and file data in cleartext.",
            evidence=["TCP port 21 open (connect scan)"],
            recommendation="Replace with SFTP or FTPS if file transfer is required.",
            risk_score=5.5,
        )]
    return []


def rule_smb_netbios_exposed(summary):
    findings = []
    if 445 in summary["open_ports"]:
        findings.append(Finding(
            id="NET-003", title="SMB exposed", severity="high",
            category="exposed_service", confidence="confirmed",
            port=445, service="SMB",
            description=(
                "SMB has historically been the entry point for major worm-class "
                "exploits (e.g. EternalBlue/WannaCry). Port being open does not "
                "confirm vulnerability -- patch level cannot be determined from a "
                "banner grab alone."
            ),
            evidence=["TCP port 445 open (connect scan)", "SMB dialect/patch level not verified"],
            recommendation="Confirm this host is fully patched; restrict SMB to trusted hosts only; disable if unused.",
            risk_score=8.5,
        ))
    if 139 in summary["open_ports"]:
        findings.append(Finding(
            id="NET-004", title="NetBIOS exposed", severity="medium",
            category="exposed_service", confidence="confirmed",
            port=139, service="NetBIOS-SSN",
            description="Legacy NetBIOS session service, generally superseded by SMB directly over 445.",
            evidence=["TCP port 139 open (connect scan)"],
            recommendation="Disable NetBIOS over TCP/IP if modern SMB direct-hosting is sufficient.",
            risk_score=4.0,
        ))
    return findings


def rule_rdp_exposed(summary):
    if 3389 in summary["open_ports"]:
        return [Finding(
            id="NET-005", title="RDP exposed", severity="high",
            category="exposed_service", confidence="confirmed",
            port=3389, service="RDP",
            description="RDP is one of the most common ransomware entry vectors, especially when reachable beyond the local network.",
            evidence=["TCP port 3389 open (connect scan)"],
            recommendation="Restrict RDP to VPN-only access, enforce Network Level Authentication, disable if unused.",
            risk_score=8.0,
        )]
    return []


def rule_dns_interception(summary):
    if summary.get("dns_validated") is False:
        evidence = ["TCP port 53 open (connect scan)"]
        if summary.get("dns_detail"):
            evidence.append(f"UDP DNS validation: {summary['dns_detail']}")
        return [Finding(
            id="NET-006", title="Potential DNS interception", severity="medium",
            category="misconfiguration", confidence="heuristic",
            port=53, service="DNS",
            description=(
                "TCP/53 completed a handshake but no genuine DNS service answered "
                "over UDP -- consistent with router-level DNS interception/hijacking "
                "rather than a real resolver running on this host."
            ),
            evidence=evidence,
            recommendation=(
                "Confirm this is expected (parental controls / ad-blocking DNS in "
                "router settings). If unexpected, investigate as possible on-path "
                "DNS manipulation."
            ),
            risk_score=5.0,
        )]
    return []


# HTTP header findings are deliberately low severity, per the same
# philosophy as the rest of the engine: a missing header is a security
# hygiene gap, not proof of a vulnerability. HSTS is only checked on
# HTTPS (443) -- the header is meaningless on plain HTTP and flagging
# its absence there would be misleading, not useful.
_HTTP_HEADER_CHECKS = [
    ("NET-007", "x_frame_options", "Missing X-Frame-Options header",
     "Add X-Frame-Options (or a frame-ancestors CSP directive) for clickjacking protection.", None),
    ("NET-008", "content_security_policy", "Missing Content-Security-Policy header",
     "Add a Content-Security-Policy header to reduce XSS/injection blast radius.", None),
    ("NET-009", "strict_transport_security", "Missing Strict-Transport-Security header",
     "Add HSTS to force browsers to use HTTPS for future requests to this host.", 443),
    ("NET-010", "x_content_type_options", "Missing X-Content-Type-Options header",
     "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.", None),
]


def rule_http_missing_headers(summary):
    findings = []
    for port, svc_evidence in summary["services"].items():
        headers = svc_evidence.get("headers")
        if not headers:
            continue  # no HTTP response captured for this port -- nothing to check

        for finding_id, header_key, description, recommendation, required_port in _HTTP_HEADER_CHECKS:
            if required_port is not None and port != required_port:
                continue
            if not headers.get(header_key):
                findings.append(Finding(
                    id=finding_id, title=description, severity="low",
                    category="misconfiguration", confidence="confirmed",
                    port=port, service=svc_evidence["name"],
                    description=description,
                    evidence=[f"HTTP response received on port {port}", f"Header not present: {header_key.replace('_', '-')}"],
                    recommendation=recommendation, risk_score=2.5,
                ))
    return findings


RULES = [
    rule_telnet_open,
    rule_ftp_plaintext,
    rule_smb_netbios_exposed,
    rule_rdp_exposed,
    rule_dns_interception,
    rule_http_missing_headers,
]

# Ports considered high-risk if newly opened between scans -- used by
# the scan-comparison diff to distinguish "New exposure" (worth an
# alert) from routine new services (e.g. a new HTTP server).
HIGH_RISK_PORTS = {21, 23, 139, 445, 3389}


def evaluate_security(summary):
    """Runs every rule against a host's summary dict and returns the combined findings list."""
    findings = []
    for rule in RULES:
        findings.extend(rule(summary))
    return findings


def get_network_info():
    """
    Automatically detects the default routing interface and local subnet.
    """
    try:
        iface_name, _, _, local_ip = scapy.conf.route.route("0.0.0.0")
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
        return subnet, iface_name, local_ip
    except Exception as e:
        print(f"[-] Advanced routing detection failed: {e}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
            return subnet, scapy.conf.iface, local_ip
        except Exception as e2:
            print(f"[-] Fallback detection failed: {e2}")
            return "192.168.1.0/24", scapy.conf.iface, "192.168.1.x"


def discover_devices(ip_range, active_iface):
    """Send ARP requests to discover active devices and their MAC addresses."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(
        arp_request_broadcast,
        timeout=2,
        verbose=False,
        iface=active_iface
    )[0]

    discovered = {}
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        discovered[ip] = mac

    return discovered


def get_hostname(ip):
    """Attempt to resolve the hostname via DNS/mDNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def scan_ports(ip, ports):
    """Perform a basic TCP connect scan on a specified list of ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


# ------------------------------------------------------------------
# SERVICE + VERSION DETECTION
# ------------------------------------------------------------------

# Well-known port -> expected service name, used both for display and
# to decide which active probe (if any) to send.
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS-SSN",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-Alt",
}

# Regex patterns used to pull a version string out of a raw banner.
# Kept intentionally simple/readable rather than exhaustive -- add
# patterns here as you encounter services you care about.
VERSION_PATTERNS = [
    re.compile(r"SSH-\d\.\d-(?P<ver>[\w.\-_]+)"),                     # SSH
    re.compile(r"Server:\s*(?P<ver>[^\r\n]+)", re.IGNORECASE),        # HTTP
    re.compile(r"220[- ].*?(?P<ver>[A-Za-z0-9_.\-]+ \d[\w.\-]*)"),    # FTP/SMTP banners
    re.compile(r"\+OK.*?(?P<ver>[A-Za-z0-9_.\-]+ \d[\w.\-]*)"),       # POP3
]


def _extract_version(banner):
    for pattern in VERSION_PATTERNS:
        match = pattern.search(banner)
        if match:
            return match.group("ver").strip()
    return None


def _grab_banner(ip, port, timeout=1.5):
    """
    Passive banner grab: connect and read whatever the service sends
    unsolicited (works for FTP, SSH, SMTP, POP3, etc.).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def _probe_http(ip, port, timeout=1.5, use_tls=False):
    """
    Active probe for HTTP/HTTPS: these services stay silent until
    spoken to, so a passive grab returns nothing. Sending a minimal
    HEAD request gets us the Server header where present.
    """
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # scanning by IP; cert validation isn't the goal here
            sock = ctx.wrap_socket(raw_sock)
        else:
            sock = raw_sock

        request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        data = sock.recv(2048)
        sock.close()
        return data.decode(errors="ignore")
    except Exception:
        return ""


def _parse_http_headers(raw_response):
    """
    Parses a raw HTTP response into a dict of security-relevant headers.
    Checks presence only (not header *correctness* -- e.g. a malformed
    CSP still counts as "present" here). Deeper header-value validation
    is a natural Phase 3-style follow-up, not a hygiene check.
    """
    header_dict = {}
    for line in raw_response.split("\r\n")[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        header_dict[key.strip().lower()] = value.strip()

    return {
        "server": header_dict.get("server"),
        "strict_transport_security": "strict-transport-security" in header_dict,
        "content_security_policy": "content-security-policy" in header_dict,
        "x_frame_options": "x-frame-options" in header_dict,
        "x_content_type_options": "x-content-type-options" in header_dict,
    }


def detect_service(ip, port, timeout=1.5):
    """
    Returns a service evidence dict:
        {"name": str, "version": str|None, "banner": str|None, "confidence": str}

    confidence reflects how the identification was made, not a guess
    about correctness:
      "high"   - a banner was captured AND a version was parsed from it
      "medium" - a banner was captured but no version could be parsed
      "low"    - no banner at all; name is purely the port-number default

    This distinction matters for a consumer (human or AI agent) deciding
    how much to trust "SSH detected" vs. "SSH detected from banner
    SSH-2.0-OpenSSH_9.3".
    """
    service_name = COMMON_SERVICES.get(port, "Unknown")
    banner = _grab_banner(ip, port, timeout)

    if not banner and port in (80, 8080):
        banner = _probe_http(ip, port, timeout, use_tls=False)
    elif not banner and port == 443:
        banner = _probe_http(ip, port, timeout, use_tls=True)

    version = _extract_version(banner) if banner else None

    # If banner told us something the port number didn't (e.g. a
    # service running on a non-standard port), prefer the banner.
    if banner.startswith("SSH-"):
        service_name = "SSH"
    elif "FTP" in banner[:20].upper() or banner.startswith("220"):
        service_name = service_name if service_name != "Unknown" else "FTP/SMTP-family"

    if version:
        confidence = "high"
    elif banner:
        confidence = "medium"
    else:
        confidence = "low"

    headers = None
    if port in (80, 443, 8080) and banner.startswith("HTTP/"):
        headers = _parse_http_headers(banner)

    # Sanitize for safe display and JSON export: strip non-printable
    # bytes, collapse whitespace/newlines, cap length so a hostile or
    # misbehaving service can't inject control characters or bloat output.
    clean_banner = "".join(ch for ch in banner if ch.isprintable())
    clean_banner = re.sub(r"\s+", " ", clean_banner).strip()[:200]

    return {
        "name": service_name,
        "version": version,
        "banner": clean_banner if clean_banner else None,
        "confidence": confidence,
        "headers": headers,
    }


# ------------------------------------------------------------------
# OS FINGERPRINTING (best-effort, TTL + TCP window heuristic)
#
# This is NOT equivalent to nmap's -O (which correlates a dozen+
# signals against a large fingerprint database). It's a cheap
# heuristic based on the fact that most OS families ship with a
# distinct default initial TTL:
#   Linux/macOS/*BSD  -> 64
#   Windows           -> 128
#   Cisco/Solaris/AIX -> 255
# Intermediate hops decrement TTL by 1 each, so we round the
# *observed* TTL up to the nearest of these defaults and note the
# implied hop count. On a LAN (hop count 0-1) this is fairly
# reliable; across routed networks it degrades and should be
# labeled as low-confidence.
# ------------------------------------------------------------------

TTL_GUESSES = [(64, "Linux/Unix/macOS"), (128, "Windows"), (255, "Network device / Solaris / AIX")]


def fingerprint_os(ip, open_ports, active_iface, timeout=1.5, retries=1):
    """
    Sends a TCP SYN to an open port (falls back to ICMP echo if no
    ports are open) and infers OS family from the response TTL and
    TCP window size. Returns (os_guess, confidence_note).

    active_iface is required and explicitly passed to scapy -- without
    it, scapy's own route lookup can silently pick a different NIC
    than the one ARP discovery used (VPN adapters, Docker/WSL virtual
    bridges, etc.), causing the probe to vanish with no error at all.
    """
    ttl = None
    window = None
    error_detail = None

    for attempt in range(retries + 1):
        with SCAPY_LOCK:
            try:
                if open_ports:
                    pkt = scapy.IP(dst=ip) / scapy.TCP(dport=open_ports[0], flags="S")
                    resp = scapy.sr1(pkt, timeout=timeout, verbose=False, iface=active_iface)
                    if resp and resp.haslayer(scapy.TCP):
                        ttl = resp[scapy.IP].ttl
                        window = resp[scapy.TCP].window
                        if resp[scapy.TCP].flags == "SA":
                            rst = scapy.IP(dst=ip) / scapy.TCP(
                                dport=open_ports[0], sport=resp[scapy.TCP].dport, flags="R",
                                seq=resp[scapy.TCP].ack
                            )
                            scapy.send(rst, verbose=False, iface=active_iface)
                else:
                    resp = scapy.sr1(scapy.IP(dst=ip) / scapy.ICMP(), timeout=timeout,
                                      verbose=False, iface=active_iface)
                    if resp and resp.haslayer(scapy.IP):
                        ttl = resp[scapy.IP].ttl
            except PermissionError as e:
                error_detail = f"permission denied opening raw socket ({e}) -- rerun with sudo/admin"
                break  # retrying won't fix a permissions problem
            except OSError as e:
                error_detail = f"OS-level socket error ({e})"
                break
            except Exception as e:
                error_detail = f"{type(e).__name__}: {e}"
                break

        if ttl is not None:
            break  # got a usable response, no need to retry

    if ttl is None:
        reason = error_detail if error_detail else f"no response after {retries + 1} attempt(s) on iface={active_iface} (timeout or filtered)"
        return "Unknown", reason, "n/a"

    best_guess = min(TTL_GUESSES, key=lambda pair: abs(pair[0] - ttl) if ttl <= pair[0] else float("inf"))
    hop_estimate = best_guess[0] - ttl
    confidence = "high" if hop_estimate <= 1 else ("medium" if hop_estimate <= 4 else "low")

    detail = f"TTL={ttl} (~{hop_estimate} hop{'s' if hop_estimate != 1 else ''}), confidence={confidence}"
    if window:
        detail += f", window={window}"

    return best_guess[1], detail, confidence


# ------------------------------------------------------------------

def analyze_host(ip, mac, ports, active_iface):
    """
    Worker function for threads: gathers hostname, vendor, open ports,
    services (with evidence), OS guess, and security findings. Returns
    (report_str, summary_dict) -- the dict feeds both the aggregate
    summary and the JSON export.
    """
    hostname = get_hostname(ip)
    vendor = get_vendor(mac)
    open_ports = scan_ports(ip, ports)

    services = {}  # port -> evidence dict (name, version, banner, confidence)
    service_lines = []
    dns_validated = None  # stays None unless port 53 is actually open and checked
    dns_detail = None

    for port in open_ports:
        evidence = detect_service(ip, port)
        port_str = f"{port}/tcp"
        version_str = evidence["version"] if evidence["version"] else "(undetermined)"

        # Port 53 needs its own line format: a completed TCP handshake
        # doesn't prove a real resolver is behind it (see
        # validate_dns_service). Confirm before labeling it DNS.
        if port == 53:
            dns_validated, dns_detail = validate_dns_service(ip)
            evidence["dns_validated"] = dns_validated
            if dns_validated:
                service_lines.append(f"    {port_str:<8} {evidence['name']:<12} version: {version_str}  [{dns_detail}]")
            else:
                service_lines.append(f"    {port_str:<8} {evidence['name']:<12} UNVERIFIED  [{dns_detail}]")
        else:
            evidence_note = f" (from banner: {evidence['banner']})" if evidence["banner"] and evidence["version"] else ""
            service_lines.append(f"    {port_str:<8} {evidence['name']:<12} version: {version_str}{evidence_note}")

        services[port] = evidence

    os_guess, os_detail, os_confidence = fingerprint_os(ip, open_ports, active_iface)

    summary = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "os_guess": os_guess,
        "os_confidence": os_confidence,
        "open_ports": open_ports,
        "services": services,
        "dns_validated": dns_validated if 53 in open_ports else None,
        "dns_detail": dns_detail if 53 in open_ports else None,
    }

    findings = evaluate_security(summary)
    summary["findings"] = findings

    result_str = f"Target: {ip}\n"
    result_str += f"MAC:    {mac}\n"
    result_str += f"Vendor: {vendor}\n"
    result_str += f"Host:   {hostname}\n"
    result_str += f"OS:     {os_guess}  [{os_detail}]\n"

    if open_ports:
        result_str += "Open Ports / Services:\n" + "\n".join(service_lines) + "\n"
    else:
        result_str += "Open:   None found in common list\n"

    if findings:
        result_str += "Security Findings:\n"
        for f in findings:
            result_str += f"    [{f.severity.upper():<6}] {f.id}  {f.port}/{f.service}  risk={f.risk_score}/10: {f.description}\n"
            result_str += f"             -> {f.recommendation}\n"

    result_str += "-" * 60
    return result_str, summary


def print_summary(results, elapsed_seconds):
    """
    Aggregate view across every host scanned this run: OS mix, most
    common services/ports on the network, and hosts with nothing open.
    Separate from the per-host report so you can skim the shape of the
    whole network without reading every block above it.
    """
    total_hosts = len(results)
    os_counts = {}                 # os_name -> total count
    os_confidence_counts = {}      # os_name -> {confidence_level: count}
    port_service_counts = {}       # (port, name) -> count of hosts with it open
    hosts_no_open_ports = []

    for r in results:
        os_name = r["os_guess"]
        conf = r.get("os_confidence", "n/a")

        os_counts[os_name] = os_counts.get(os_name, 0) + 1
        os_confidence_counts.setdefault(os_name, {})
        os_confidence_counts[os_name][conf] = os_confidence_counts[os_name].get(conf, 0) + 1

        if not r["open_ports"]:
            hosts_no_open_ports.append(r["ip"])

        for port, evidence in r["services"].items():
            key = (port, evidence["name"])
            port_service_counts[key] = port_service_counts.get(key, 0) + 1

    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Hosts scanned:        {total_hosts}")
    print(f"Total scan time:      {elapsed_seconds:.1f}s")

    print("\nOS breakdown (with fingerprint confidence):")
    for os_name, count in sorted(os_counts.items(), key=lambda kv: -kv[1]):
        conf_breakdown = os_confidence_counts[os_name]
        # Order confidence levels meaningfully rather than alphabetically
        conf_order = ["high", "medium", "low", "n/a"]
        conf_str = ", ".join(
            f"{level}: {conf_breakdown[level]}"
            for level in conf_order
            if level in conf_breakdown
        )
        print(f"    {os_name:<25} {count:<3} ({conf_str})")

    print("\nMost common open services (network-wide):")
    if port_service_counts:
        ranked = sorted(port_service_counts.items(), key=lambda kv: -kv[1])
        for (port, name), count in ranked[:10]:
            print(f"    {port}/tcp  {name:<12} on {count} host(s)")
    else:
        print("    None found.")

    print(f"\nHosts with no open ports in scan list: {len(hosts_no_open_ports)}")
    for ip in hosts_no_open_ports:
        print(f"    {ip}")

    print("\nSecurity findings:")
    severity_order = ["high", "medium", "low", "info"]
    findings_by_severity = {s: [] for s in severity_order}
    for r in results:
        for f in r.get("findings", []):
            findings_by_severity[f.severity].append((r["ip"], f))

    total_findings = sum(len(v) for v in findings_by_severity.values())
    if total_findings == 0:
        print("    None of the current rule set matched. Note: this checks for a small,")
        print("    fixed set of commonly risky configurations -- it is not a vulnerability")
        print("    scan and an absence of findings here is not a clean bill of health.")
    else:
        for severity in severity_order:
            items = findings_by_severity[severity]
            if not items:
                continue
            print(f"  {severity.upper()} ({len(items)}):")
            for ip, f in items:
                print(f"    {ip:<16} {f.id}  {f.port}/{f.service}  risk={f.risk_score}/10: {f.description}")
                print(f"    {'':<16} -> {f.recommendation}")

    print("=" * 60)


def save_results(results, target_subnet, elapsed_seconds, output_dir="scan_results", scanner_name="NetGuard"):
    """
    Writes the full scan as structured JSON -- this is the bridge
    between the scan engine and any downstream consumer (an AI agent,
    a dashboard, a diffing tool for future scan comparison).

    Uses dataclasses.asdict() for Finding objects rather than manually
    rebuilding each dict field by field, so adding a field to Finding
    later (e.g. when the CVE/CVSS layer lands) shows up here for free
    with no serialization code to update.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
    filename_ts = time.strftime("%Y%m%d_%H%M%S")

    assets = []
    for r in results:
        services_list = [
            {"port": port, **evidence}
            for port, evidence in sorted(r["services"].items())
        ]
        findings_list = [asdict(f) for f in r.get("findings", [])]

        assets.append({
            "hostname": r["hostname"],
            "ip": r["ip"],
            "mac": r["mac"],
            "vendor": r.get("vendor", "Unknown"),
            "os": r["os_guess"],
            "os_confidence": r.get("os_confidence", "n/a"),
            "services": services_list,
            "findings": findings_list,
        })

    output = {
        "scan_metadata": {
            "time": timestamp_iso,
            "scanner": scanner_name,
            "target_subnet": target_subnet,
            "duration_seconds": round(elapsed_seconds, 1),
            "host_count": len(assets),
        },
        "assets": assets,
    }

    filepath = os.path.join(output_dir, f"scan_{filename_ts}.json")
    try:
        with open(filepath, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n[+] JSON results written to {filepath}")
        return filepath
    except Exception as e:
        print(f"[!] Failed to write JSON results: {e}")
        return None


def load_previous_scan(output_dir="scan_results"):
    """
    Loads the most recent previously-saved scan JSON (by filename
    timestamp) to diff against. Returns None if this is the first scan
    on record -- that's a normal state, not an error, and callers
    should treat it as "no baseline yet" rather than a failure.
    """
    if not os.path.isdir(output_dir):
        return None

    scan_files = sorted(
        f for f in os.listdir(output_dir)
        if f.startswith("scan_") and f.endswith(".json")
    )
    if not scan_files:
        return None

    latest_path = os.path.join(output_dir, scan_files[-1])
    try:
        with open(latest_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Could not load previous scan ({latest_path}): {e}")
        return None


def compare_scans(previous, current_results):
    """
    Diffs the current in-memory scan against a previously saved one,
    keyed by MAC address rather than IP.

    Why MAC: on a DHCP network, the same physical device can get a
    different IP between scans. Diffing by IP would misreport that as
    "device X disappeared" + "new device Y appeared" -- two false
    events for one real (and usually benign) DHCP lease renewal.
    Keying on MAC instead correctly reports that as a single
    "IP changed" event and only flags a genuinely new MAC as a new
    device. (Caveat worth knowing: modern phones/laptops increasingly
    randomize MAC addresses by default, which would show up here as a
    false "new device" -- there's no way around that from a LAN-side
    scanner; it's a real limitation, not a bug.)

    Returns None if there's no previous scan to compare against.
    """
    if previous is None:
        return None

    prev_by_mac = {a["mac"].lower(): a for a in previous.get("assets", [])}
    curr_by_mac = {r["mac"].lower(): r for r in current_results}

    new_devices = []
    ip_changes = []
    service_changes = []

    for mac, curr in curr_by_mac.items():
        if mac not in prev_by_mac:
            new_devices.append({"mac": curr["mac"], "ip": curr["ip"], "hostname": curr["hostname"]})
            continue

        prev = prev_by_mac[mac]

        if prev.get("ip") != curr["ip"]:
            ip_changes.append({
                "mac": curr["mac"], "hostname": curr["hostname"],
                "previous_ip": prev.get("ip"), "current_ip": curr["ip"],
            })

        prev_ports = {s["port"]: s["name"] for s in prev.get("services", [])}
        curr_ports = {port: evidence["name"] for port, evidence in curr["services"].items()}

        added = {p: n for p, n in curr_ports.items() if p not in prev_ports}
        removed = {p: n for p, n in prev_ports.items() if p not in curr_ports}

        if added or removed:
            service_changes.append({
                "mac": curr["mac"], "hostname": curr["hostname"], "ip": curr["ip"],
                "previous_services": [f"{p}/tcp {n}" for p, n in sorted(prev_ports.items())],
                "current_services": [f"{p}/tcp {n}" for p, n in sorted(curr_ports.items())],
                "new_open_ports": [f"{p}/tcp {n}" for p, n in sorted(added.items())],
                "closed_ports": [f"{p}/tcp {n}" for p, n in sorted(removed.items())],
                "new_exposures": [f"{n}" for p, n in sorted(added.items()) if p in HIGH_RISK_PORTS],
            })

    missing_devices = [
        {"mac": a["mac"], "ip": a.get("ip"), "hostname": a.get("hostname")}
        for mac, a in prev_by_mac.items() if mac not in curr_by_mac
    ]

    return {
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "ip_changes": ip_changes,
        "service_changes": service_changes,
    }


def print_asset_changes(diff):
    """Prints the scan-comparison diff in the SOC-report style: new/missing devices, DHCP events, and service/exposure changes."""
    print("\n" + "=" * 60)
    print("ASSET CHANGES (vs previous scan)")
    print("=" * 60)

    if diff is None:
        print("    No previous scan found -- this run is the new baseline.")
        print("=" * 60)
        return

    has_changes = any([diff["new_devices"], diff["missing_devices"], diff["ip_changes"], diff["service_changes"]])
    if not has_changes:
        print("    No changes detected since previous scan.")
        print("=" * 60)
        return

    for d in diff["new_devices"]:
        print("NEW DEVICE:")
        print(f"    Hostname: {d['hostname']}")
        print(f"    MAC:      {d['mac']}")
        print(f"    IP:       {d['ip']}\n")

    for d in diff["missing_devices"]:
        print("DEVICE NO LONGER RESPONDING:")
        print(f"    Hostname:      {d['hostname']}")
        print(f"    MAC:           {d['mac']}")
        print(f"    Last known IP: {d['ip']}\n")

    for d in diff["ip_changes"]:
        print("IP CHANGED (DHCP event):")
        print(f"    Hostname: {d['hostname']}")
        print(f"    MAC:      {d['mac']}")
        print(f"    {d['previous_ip']} -> {d['current_ip']}\n")

    for d in diff["service_changes"]:
        print("SERVICE CHANGE:")
        print(f"    Device: {d['hostname']}")
        print(f"    MAC:    {d['mac']}")
        print("    Previous:")
        for s in d["previous_services"]:
            print(f"        {s}")
        print("    Current:")
        for s in d["current_services"]:
            print(f"        {s}")
        if d["new_exposures"]:
            print("    New exposure:")
            for name in d["new_exposures"]:
                print(f"        {name} detected")
        if d["closed_ports"]:
            print("    Closed since last scan:")
            for s in d["closed_ports"]:
                print(f"        {s}")
        print()

    print("=" * 60)


def confirm_authorization(target_subnet):
    """
    Minimal consent gate. Active scanning (banner grabs, SYN probes)
    is meaningfully more intrusive than passive ARP discovery -- get
    an explicit, logged confirmation before it runs.
    """
    print("=" * 60)
    print("AUTHORIZATION REQUIRED")
    print(f"This will actively probe every host on {target_subnet},")
    print("including service banner grabs and OS fingerprint probes.")
    print("Only run this against networks you own or are explicitly")
    print("authorized to test.")
    print("=" * 60)
    answer = input("Type 'yes' to confirm you are authorized to scan this network: ").strip().lower()
    if answer != "yes":
        print("[-] Authorization not confirmed. Exiting.")
        return False

    try:
        with open("scan_log.txt", "a") as log:
            log.write(f"{time.ctime()} - Authorized scan started on {target_subnet}\n")
    except Exception as e:
        print(f"[!] Could not write scan log: {e}")

    return True


def main():
    print("Initializing Network Scanner...")

    if not _VENDOR_LOOKUP_AVAILABLE:
        print("[!] 'manuf' not installed -- MAC vendor lookup will report 'Unknown'.")
        print("    Install with: pip install manuf")

    target_subnet, active_iface, local_ip = get_network_info()

    print("=" * 60)
    print(f"[*] Local IP Detected: {local_ip}")
    print(f"[*] Target Subnet:     {target_subnet}")
    print(f"[*] Active Interface:  {active_iface}")
    print("=" * 60)

    if not confirm_authorization(target_subnet):
        return

    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]
    max_threads = 20
    all_devices = {}

    for i in range(3):
        print(f"\n--- Discovery Scan {i + 1}/3 ---")
        current_scan = discover_devices(target_subnet, active_iface)

        new_devices = 0
        for ip, mac in current_scan.items():
            if ip not in all_devices:
                all_devices[ip] = mac
                new_devices += 1

        print(f"Found {len(current_scan)} active devices ({new_devices} new).")

        if i < 2:
            print("Waiting 10 seconds before the next sweep...")
            time.sleep(10)

    print(f"\nDiscovery complete. Found {len(all_devices)} unique devices total.")
    print("=" * 60)

    if len(all_devices) == 0:
        print("No devices found. Ensure you are running this script with Administrator/sudo privileges!")
        return

    print("Starting threaded deep scan (Hostnames, Ports, Services, Versions, OS)...\n")

    scan_start = time.time()
    all_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {
            executor.submit(analyze_host, ip, mac, common_ports, active_iface): ip
            for ip, mac in all_devices.items()
        }

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                report, summary = future.result()
                print(report)
                all_results.append(summary)
            except Exception as exc:
                print(f"{ip} generated an exception: {exc}")

    elapsed = time.time() - scan_start
    print_summary(all_results, elapsed)

    # Must load the previous scan before save_results() writes the new
    # one -- otherwise this run would end up diffed against itself.
    previous_scan = load_previous_scan()
    diff = compare_scans(previous_scan, all_results)
    print_asset_changes(diff)

    previous_scan = load_previous_scan()
    diff = compare_scans(previous_scan, all_results)
    print_asset_changes(diff)

    json_file = save_results(
        all_results,
        target_subnet,
        elapsed
    )

    import sys  
    import subprocess

    subprocess.run(
    [
        sys.executable,
        "filter.py",
        json_file
    ],
    check=True
)


    filtered_file = json_file.replace(
    ".json",
    "_filtered.json"
)


    subprocess.run(
    [
        sys.executable,
        "agent.py",
        filtered_file
    ],
    check=True
)


if __name__ == "__main__":
    main()
