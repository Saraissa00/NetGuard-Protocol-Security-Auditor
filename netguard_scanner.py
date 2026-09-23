#!/usr/bin/env python3
"""
NetGuard - DNS Security Auditor
================================
Detects DNS hijacking by comparing the local DNS resolver's answer
against Google's trusted public resolver (8.8.8.8).

  Layer 7 (Application) : DNS query/response
  Layer 3 (Network)     : UDP packets routed to 8.8.8.8

Requirements:
  Python 3.x standard library only (socket, struct) - no pip installs needed.
"""

import socket
import struct
import os
import sys
import time
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
#  TERMINAL COLOR CODES  (ANSI escape sequences)
# ──────────────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


DNS_PORT     = 53
DNS_TIMEOUT  = 5


def _print_usage() -> None:
    print(f"\n{C.BOLD}Usage:{C.RESET}")
    print("  python netguard_scanner.py [domain] [dns_server]")
    print(f"\n{C.BOLD}Arguments:{C.RESET}")
    print("  domain      Domain to audit  (default: google.com)")
    print("  dns_server  Trusted DNS IP   (default: 8.8.8.8)")
    print(f"\n{C.BOLD}Examples:{C.RESET}")
    print("  python netguard_scanner.py")
    print("  python netguard_scanner.py github.com")
    print("  python netguard_scanner.py github.com 1.1.1.1\n")


def _validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    return all(label.replace("-", "").isalnum() for label in labels if label)


def _parse_args() -> tuple[str, str]:
    args = sys.argv[1:]

    if any(a in ("--help", "-h") for a in args):
        _print_usage()
        sys.exit(0)

    if len(args) > 2:
        print(f"{C.RED}[ERROR] Too many arguments.{C.RESET}")
        _print_usage()
        sys.exit(1)

    domain = args[0] if len(args) >= 1 else "google.com"
    dns_server = args[1] if len(args) == 2 else "8.8.8.8"

    if not _validate_domain(domain):
        print(f"{C.RED}[ERROR] Invalid domain: '{domain}'{C.RESET}")
        _print_usage()
        sys.exit(1)

    if not _validate_ip(dns_server):
        print(f"{C.RED}[ERROR] Invalid DNS server IP: '{dns_server}'{C.RESET}")
        _print_usage()
        sys.exit(1)

    return domain, dns_server


TEST_DOMAIN, TRUSTED_DNS = _parse_args()


# ──────────────────────────────────────────────────────────────────────────────
#  DNS QUERY BUILDER
#  Constructs a minimal DNS A-record query packet from scratch using struct.
#  DNS runs over UDP at Layer 4, carried by IP at Layer 3 (Application layer 7).
# ──────────────────────────────────────────────────────────────────────────────
def _build_dns_query(domain: str) -> bytes:
    transaction_id = 0x1234
    flags          = 0x0100   # Standard query, recursion desired
    qdcount        = 1        # One question
    header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, 0, 0, 0)

    # Encode domain as DNS labels: "google.com" → \x06google\x03com\x00
    question = b""
    for label in domain.split("."):
        encoded = label.encode()
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"
    question += struct.pack(">HH", 1, 1)   # QTYPE=A, QCLASS=IN

    return header + question


def _parse_dns_response(data: bytes) -> str | None:
    """Extracts the first A-record IP from a raw DNS response packet."""
    # ── Layer 7: DNS response layout ──────────────────────────────────────────
    # Header is 12 bytes. Answers follow the question section.
    # Each answer's RDATA for an A record is 4 bytes (IPv4 address).
    if len(data) < 12:
        return None

    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return None

    # Skip the header (12 bytes) and the question section
    offset = 12
    # Skip question: scan past the QNAME labels
    while offset < len(data) and data[offset] != 0:
        offset += data[offset] + 1
    offset += 1 + 4   # null terminator + QTYPE + QCLASS (4 bytes)

    # Parse the first answer record
    for _ in range(ancount):
        if offset + 10 > len(data):
            break
        # NAME (2 bytes if pointer), TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        offset += 2   # NAME (pointer or label, skip)
        rtype    = struct.unpack(">H", data[offset:offset+2])[0]
        offset  += 8  # TYPE + CLASS + TTL
        rdlength = struct.unpack(">H", data[offset:offset+2])[0]
        offset  += 2

        if rtype == 1 and rdlength == 4:   # A record = IPv4
            ip = ".".join(str(b) for b in data[offset:offset+4])
            return ip

        offset += rdlength

    return None


def resolve(domain: str, dns_server: str) -> str | None:
    """
    Sends a DNS A-query for `domain` directly to `dns_server` over UDP.

    Layer 3/4: a UDP socket is opened and the packet is sent to port 53
    on the target DNS server. No OS resolver cache is consulted.
    """
    query = _build_dns_query(domain)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DNS_TIMEOUT)
        sock.sendto(query, (dns_server, DNS_PORT))
        data, _ = sock.recvfrom(512)
        sock.close()
        return _parse_dns_response(data)
    except Exception:
        return None


def resolve_via_os(domain: str) -> str | None:
    """Resolves `domain` using the OS resolver (local/DHCP-assigned DNS server)."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  MAIN AUDIT LOGIC
# ──────────────────────────────────────────────────────────────────────────────
def run_dns_audit() -> None:
    W = 56

    print(f"\n{C.BOLD}{C.CYAN}")
    print("+==================================================+")
    print("|         NetGuard  DNS Security Auditor           |")
    print("|         Layer 3 / Layer 7  DNS Verification      |")
    print("+==================================================+")
    print(C.RESET)

    print(f"{C.CYAN}[*] Resolving {TEST_DOMAIN} via local DNS (your router/ISP)...{C.RESET}")
    local_ip = resolve_via_os(TEST_DOMAIN)
    if local_ip:
        print(f"    Local  DNS result : {TEST_DOMAIN} -> {local_ip}")
    else:
        print(f"    {C.RED}[FAIL] Local DNS could not resolve {TEST_DOMAIN}.{C.RESET}")

    print(f"\n{C.CYAN}[*] Resolving {TEST_DOMAIN} via trusted DNS ({TRUSTED_DNS})...{C.RESET}")
    trusted_ip = resolve(TEST_DOMAIN, TRUSTED_DNS)
    if trusted_ip:
        print(f"    Trusted DNS result : {TEST_DOMAIN} -> {trusted_ip}")
    else:
        print(f"    {C.RED}[FAIL] Could not reach {TRUSTED_DNS} (check internet connectivity).{C.RESET}")

    print()
    print("=" * W)
    print(f"  Audit time : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
    print("-" * W)

    def same_subnet(ip1: str, ip2: str) -> bool:
        # Compare /24 — same first 3 octets means same datacenter block,
        # which is expected for load-balanced/CDN domains (GitHub, Cloudflare, etc.)
        return ip1.rsplit(".", 1)[0] == ip2.rsplit(".", 1)[0]

    if not local_ip or not trusted_ip:
        print(f"  {C.RED}[ERROR] Could not complete DNS comparison — check your connection.{C.RESET}")
    elif same_subnet(local_ip, trusted_ip):
        print(f"  {C.GREEN}{C.BOLD}  CONNECTION SAFE (DNS Verified){C.RESET}")
        print(f"  Local  DNS : {local_ip}")
        print(f"  Trusted DNS: {trusted_ip}")
        match = "exact match" if local_ip == trusted_ip else "same /24 subnet"
        print(f"  Both resolvers agree ({match}).")
    else:
        print(f"  {C.RED}{C.BOLD}  DANGEROUS: DNS HIJACKING DETECTED{C.RESET}")
        print(f"  Local  DNS says : {local_ip}")
        print(f"  Trusted DNS says: {trusted_ip}")
        print(f"\n  {C.RED}RECOMMENDATIONS:{C.RESET}")
        print("   * Do NOT log in to any accounts on this network.")
        print("   * Enable a VPN with DNS-leak protection immediately.")
        print("   * Manually set DNS to 1.1.1.1 or 8.8.8.8 in your network settings.")

    print("=" * W)
    print()


if __name__ == "__main__":
    run_dns_audit()
