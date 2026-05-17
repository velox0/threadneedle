import socket
import ssl
import requests
import redis
import mmh3
import subprocess
import urllib3

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


def process(target_val):
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
            
    console.print(f"[bold cyan]🔍 Scanning Target:[/bold cyan] {ip} {f'[dim](from {domain})[/dim]' if domain else ''}")

    asn = asn_lookup(ip)
    if asn:
        console.print(f"   [yellow]🏢 ASN:[/yellow] {asn}")
        add_relation(ip, "ip", "hosted_on", asn, "asn")

    tls = tls_fingerprint(ip)
    if tls:
        cipher = str(tls["cipher"])
        console.print(f"   [magenta]🔒 TLS Cipher:[/magenta] {cipher}")
        add_relation(ip, "ip", "tls_cipher", cipher, "tls")

    fav = favicon_hash(ip)
    if fav:
        console.print(f"   [green]🖼️ Favicon Hash:[/green] {fav}")
        add_relation(ip, "ip", "favicon_hash", fav, "favicon")

    http = http_fingerprint(ip)
    if http and http["server"]:
        console.print(f"   [blue]🌐 HTTP Server:[/blue] {http['server']}")
        add_relation(ip, "ip", "server", http["server"], "http")

    scan = scan_ports(ip)
    if scan:
        open_ports = []
        for line in scan.splitlines():
            if "open" in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    open_ports.append(f"{parts[0]} ({parts[2]})")
        
        if open_ports:
            console.print(f"   [red]🚪 Open Ports:[/red] {', '.join(open_ports)}")

def run_worker():
    console.print("[bold cyan][*] Worker started, waiting for targets...[/bold cyan]")
    while True:
        result = r.brpop("targets", timeout=0)
        if result:
            target = result[1]
            process(target.decode())

if __name__ == "__main__":
    run_worker()
