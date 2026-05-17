import socket
import ssl
import requests
import redis
import mmh3
import subprocess
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from neo4j import GraphDatabase
from rich.console import Console
import ipaddress

console = Console()

r = redis.Redis(host="localhost", port=6379)

neo = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "password")
)

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# Redis keys
PROCESSED_SET = "processed"   # set of all IPs we've already scanned
RESCAN_MODE = False           # toggled by main.py when --rescan is used


def is_processed(ip):
    """Check if this IP has already been scanned."""
    return r.sismember(PROCESSED_SET, ip)


def mark_processed(ip):
    """Mark an IP as scanned."""
    r.sadd(PROCESSED_SET, ip)


def get_existing_data(ip):
    """Query Neo4j for all existing relationships for this IP."""
    query = """
    MATCH (x:Entity {value: $ip, type: 'ip'})-[rel:REL]->(y)
    RETURN rel.type AS rel_type, y.value AS value
    """
    existing = {}
    with neo.session() as s:
        result = s.run(query, ip=ip)
        for record in result:
            existing[record["rel_type"]] = record["value"]
    return existing


def report_change(ip, field, old_val, new_val):
    """Print a clear change report for a single field."""
    console.print(f"   [bold red]⚠ CHANGE[/bold red] [{field}]")
    console.print(f"      [dim red]  old:[/dim red] {old_val}")
    console.print(f"      [dim green]  new:[/dim green] {new_val}")


def add_relation(a, atype, rel, b, btype):

    query = """
    MERGE (x:Entity {value: $a, type: $atype})
    MERGE (y:Entity {value: $b, type: $btype})
    MERGE (x)-[:REL {type: $rel}]->(y)
    """

    with neo.session() as s:
        s.run(
            query,
            a=a,
            b=b,
            atype=atype,
            btype=btype,
            rel=rel
        )


def update_relation(ip, rel_type, old_value, new_value, new_btype):
    """Remove old relationship and create new one when a value changes."""
    delete_query = """
    MATCH (x:Entity {value: $ip, type: 'ip'})-[rel:REL {type: $rel_type}]->(y:Entity {value: $old_val})
    DELETE rel
    """
    with neo.session() as s:
        s.run(delete_query, ip=ip, rel_type=rel_type, old_val=old_value)

    add_relation(ip, "ip", rel_type, new_value, new_btype)


def asn_lookup(ip):

    try:
        result = subprocess.check_output(
            ["whois", ip],
            text=True
        )

        for line in result.splitlines():

            if "origin" in line.lower():
                return line.strip()

    except:
        pass

    return None


def tls_fingerprint(ip):

    try:

        ctx = ssl.create_default_context()

        with ctx.wrap_socket(
            socket.socket(),
            server_hostname=ip
        ) as s:

            s.settimeout(5)
            s.connect((ip, 443))

            cert = s.getpeercert()

            cipher = s.cipher()

            return {
                "issuer": cert.get("issuer"),
                "cipher": cipher
            }

    except:
        return None


def favicon_hash(ip):

    urls = [
        f"http://{ip}/favicon.ico",
        f"https://{ip}/favicon.ico"
    ]

    for url in urls:

        try:

            r = requests.get(
                url,
                timeout=5,
                verify=False,
                headers=HEADERS
            )

            if r.status_code == 200:

                h = mmh3.hash(r.content)

                return str(h)

        except:
            pass

    return None


def http_fingerprint(ip):

    try:

        r = requests.get(
            f"http://{ip}",
            timeout=5,
            headers=HEADERS
        )

        return {
            "server": r.headers.get("Server"),
            "title": r.text[:100]
        }

    except:
        return None


def scan_ports(ip):

    try:

        result = subprocess.check_output(
            [
                "nmap",
                "-Pn",
                "-sV",
                "--top-ports",
                "20",
                ip
            ],
            text=True
        )

        return result

    except:
        return None


def process(target_val, rescan=False):
    try:
        # Check if target is already an IP
        ipaddress.ip_address(target_val)
        ip = target_val
        domain = None
    except ValueError:
        # It's a domain, resolve it
        domain = target_val
        try:
            ip = socket.gethostbyname(domain)
            add_relation(domain, "domain", "resolves_to", ip, "ip")
        except:
            # Drop if it doesn't resolve
            return

    # Deduplication: skip already-processed IPs in normal mode
    if not rescan and is_processed(ip):
        return

    # In rescan mode, grab existing data for change comparison
    existing = {}
    if rescan:
        existing = get_existing_data(ip)
        console.print(f"[bold yellow]🔄 Re-scanning:[/bold yellow] {ip} {f'[dim](from {domain})[/dim]' if domain else ''}")
    else:
        console.print(f"[bold cyan]🔍 Scanning Target:[/bold cyan] {ip} {f'[dim](from {domain})[/dim]' if domain else ''}")

    changes_found = 0

    # --- ASN ---
    asn = asn_lookup(ip)
    if asn:
        if rescan and "hosted_on" in existing and existing["hosted_on"] != asn:
            report_change(ip, "ASN", existing["hosted_on"], asn)
            update_relation(ip, "hosted_on", existing["hosted_on"], asn, "asn")
            changes_found += 1
        else:
            if not rescan:
                console.print(f"   [yellow]🏢 ASN:[/yellow] {asn}")
            add_relation(ip, "ip", "hosted_on", asn, "asn")

    # --- TLS ---
    tls = tls_fingerprint(ip)
    if tls:
        cipher = str(tls["cipher"])
        if rescan and "tls_cipher" in existing and existing["tls_cipher"] != cipher:
            report_change(ip, "TLS Cipher", existing["tls_cipher"], cipher)
            update_relation(ip, "tls_cipher", existing["tls_cipher"], cipher, "tls")
            changes_found += 1
        else:
            if not rescan:
                console.print(f"   [magenta]🔒 TLS Cipher:[/magenta] {cipher}")
            add_relation(ip, "ip", "tls_cipher", cipher, "tls")

    # --- Favicon ---
    fav = favicon_hash(ip)
    if fav:
        if rescan and "favicon_hash" in existing and existing["favicon_hash"] != fav:
            report_change(ip, "Favicon Hash", existing["favicon_hash"], fav)
            update_relation(ip, "favicon_hash", existing["favicon_hash"], fav, "favicon")
            changes_found += 1
        else:
            if not rescan:
                console.print(f"   [green]🖼️ Favicon Hash:[/green] {fav}")
            add_relation(ip, "ip", "favicon_hash", fav, "favicon")

    # --- HTTP Server ---
    http = http_fingerprint(ip)
    if http and http["server"]:
        if rescan and "server" in existing and existing["server"] != http["server"]:
            report_change(ip, "HTTP Server", existing["server"], http["server"])
            update_relation(ip, "server", existing["server"], http["server"], "http")
            changes_found += 1
        else:
            if not rescan:
                console.print(f"   [blue]🌐 HTTP Server:[/blue] {http['server']}")
            add_relation(ip, "ip", "server", http["server"], "http")

    # --- Nmap ---
    scan = scan_ports(ip)
    if scan:
        open_ports = []
        for line in scan.splitlines():
            if "open" in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    open_ports.append(f"{parts[0]} ({parts[2]})")

        if open_ports:
            if not rescan:
                console.print(f"   [red]🚪 Open Ports:[/red] {', '.join(open_ports)}")

    # Rescan summary
    if rescan:
        if changes_found == 0:
            console.print(f"   [dim]✓ No changes detected[/dim]")
        else:
            console.print(f"   [bold red]⚡ {changes_found} change(s) detected![/bold red]")

    # Mark as processed
    mark_processed(ip)


def run_worker(rescan=False):
    mode = "rescan" if rescan else "discovery"
    console.print(f"[bold cyan][*] Worker started ({mode} mode), waiting for targets...[/bold cyan]")
    while True:
        result = r.brpop("targets", timeout=5)
        if result:
            target = result[1]
            process(target.decode(), rescan=rescan)
        elif rescan:
            # In rescan mode, exit when queue is drained
            console.print("[bold green][✓] Rescan complete, no more targets.[/bold green]")
            break

if __name__ == "__main__":
    run_worker()
