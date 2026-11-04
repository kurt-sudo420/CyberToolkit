#!/usr/bin/env python3
"""CyberToolkit - a small collection of network security utilities.

A learning project bringing together a few of the basic tools used in
day-to-day network security work: port scanning, file hashing, password
generation, DNS lookup, and banner grabbing.

IMPORTANT - scope of use:
    The port scanner and banner grabber connect to hosts over the network.
    Only run them against systems you own or have explicit written
    authorisation to test. Scanning hosts without permission may violate
    network policy (including university policy) and, in many jurisdictions,
    the law. When in doubt, don't.
"""

import concurrent.futures
import hashlib
import secrets
import socket
import string


# --------------------------------------------------------------------------
# Port scanner
# --------------------------------------------------------------------------

# Common ports and what usually lives on them, so output is readable.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}


def parse_ports(spec):
    """Turn a port spec into a sorted list of ints.

    Accepts:  "80"  |  "22,80,443"  |  "1-1024"  |  "22,80,8000-8100"
    Returns an empty list on anything invalid so the caller can complain.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            return []
        if "-" in part:
            try:
                lo, hi = (int(x) for x in part.split("-", 1))
            except ValueError:
                return []
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                return []
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(part)
                if not 1 <= port <= 65535:
                    return []
                ports.add(port)
            except ValueError:
                return []
    return sorted(ports)


def check_port(ip, port, timeout=0.5):
    """Return the port number if open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            return port
    return None


def port_scanner():
    ip = input("Enter IP or hostname: ").strip()

    # Resolve hostnames up front and validate, so we fail clearly rather
    # than throwing the same error once per port.
    try:
        ip = socket.gethostbyname(ip)
    except socket.gaierror:
        print("Could not resolve that host.")
        return

    spec = input("Ports [Enter for common ports]: ").strip()
    if spec:
        ports = parse_ports(spec)
        if not ports:
            print("Invalid port specification.")
            return
    else:
        ports = sorted(COMMON_PORTS)

    print(f"\nScanning {ip} ({len(ports)} ports)...\n")

    open_ports = []
    # Threaded: a sequential scan of 1024 ports at 0.5s timeout each would
    # take minutes in the worst case. A thread pool overlaps the waiting.
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for start in range(0, len(ports), 128):
            futures = [pool.submit(check_port, ip, p) for p in ports[start:start + 128]]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    result = fut.result()
                except OSError:
                    failures += 1
                    continue
                if result is not None:
                    open_ports.append(result)
    if failures:
        print(f"Socket errors prevented checking {failures} port(s).")

    if not open_ports:
        print("No open ports found.")
        return

    print("Open ports:")
    for port in sorted(open_ports):
        service = COMMON_PORTS.get(port, "unknown")
        print(f"  {port:>5}/tcp  {service}")


# --------------------------------------------------------------------------
# File hashing
# --------------------------------------------------------------------------

def hash_file():
    filename = input("File name: ").strip()
    # Read in chunks so a large file doesn't have to fit in memory.
    h = hashlib.sha256()
    try:
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except FileNotFoundError:
        print("File not found.")
        return
    except PermissionError:
        print("Permission denied.")
        return
    except OSError as e:
        print(f"Could not read file: {e}")
        return
    print(f"SHA-256: {h.hexdigest()}")


# --------------------------------------------------------------------------
# Password generator
# --------------------------------------------------------------------------

def password_generator():
    spec = input("Length [default 20]: ").strip()
    length = 20
    if spec:
        try:
            length = int(spec)
        except ValueError:
            print("Not a number; using 20.")
            length = 20
    if length < 8:
        print("Minimum length is 8; using 8.")
        length = 8
    if length > 256:
        print("Maximum length is 256; using 256.")
        length = 256

    # secrets, not random -- random is not safe for anything security-related.
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = "".join(secrets.choice(chars) for _ in range(length))
    print(password)


# --------------------------------------------------------------------------
# DNS lookup
# --------------------------------------------------------------------------

def dns_lookup():
    domain = input("Domain: ").strip()
    try:
        # getaddrinfo returns every A/AAAA record, not just the first.
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror:
        print("Domain not found.")
        return
    addresses = sorted({info[4][0] for info in infos})
    print(f"{domain} resolves to:")
    for addr in addresses:
        print(f"  {addr}")


# --------------------------------------------------------------------------
# Banner grabber
# --------------------------------------------------------------------------

def banner_grab():
    ip = input("IP or hostname: ").strip()
    port_spec = input("Port: ").strip()
    try:
        port = int(port_spec)
    except ValueError:
        print("Port must be a number.")
        return
    if not 1 <= port <= 65535:
        print("Port out of range.")
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
    except socket.timeout:
        print("Timed out (no banner received).")
        return
    except ConnectionRefusedError:
        print("Connection refused.")
        return
    except socket.gaierror:
        print("Could not resolve that host.")
        return
    except OSError as e:
        print(f"Unable to grab banner: {e}")
        return

    print(ascii(banner) if banner else "Connected, but no banner was sent.")


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

MENU = {
    "1": ("Port Scanner", port_scanner),
    "2": ("SHA-256 File Hash", hash_file),
    "3": ("Password Generator", password_generator),
    "4": ("DNS Lookup", dns_lookup),
    "5": ("Banner Grabber", banner_grab),
}


def main():
    while True:
        print("\nCyberToolkit")
        print("-" * 21)
        for key, (name, _) in MENU.items():
            print(f"{key}. {name}")
        print("6. Quit")

        choice = input("\nChoice: ").strip()
        if choice == "6":
            print("Goodbye.")
            break

        action = MENU.get(choice)
        if action is None:
            print("Invalid choice.")
            continue

        try:
            action[1]()
        except KeyboardInterrupt:
            # Let Ctrl+C abort the current tool without killing the program.
            print("\nCancelled.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye.")
