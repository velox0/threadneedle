import base64
import time
import redis
import requests

from cryptography import x509
from rich.console import Console

console = Console()
r = redis.Redis(host="localhost", port=6379)

# Multiple CT log endpoints for redundancy
CT_LOGS = [
    {
        "name": "Google Argon 2025h1",
        "url": "https://ct.googleapis.com/logs/us1/argon2025h1",
    },
    {
        "name": "Google Argon 2025h2",
        "url": "https://ct.googleapis.com/logs/us1/argon2025h2",
    },
    {
        "name": "Google Xenon 2025h1",
        "url": "https://ct.googleapis.com/logs/eu1/xenon2025h1",
    },
]

BATCH_SIZE = 256  # entries per fetch
BACKLOG = 500    # how far back from the tip to start (instant data)


def get_tree_size(log_url):
    """Get the current tree size (total entries) from a CT log."""
    resp = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
    resp.raise_for_status()
    return resp.json()["tree_size"]


def fetch_entries(log_url, start, end):
    """Fetch a batch of CT log entries."""
    resp = requests.get(
        f"{log_url}/ct/v1/get-entries",
        params={"start": start, "end": end},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("entries", [])


def parse_domains(entry):
    """Extract domains from a CT log entry's leaf certificate."""
    try:
        leaf = base64.b64decode(entry["leaf_input"])
        # MerkleTreeLeaf: version(1) + type(1) + timestamp(8) + entry_type(2)
        entry_type = int.from_bytes(leaf[10:12], "big")

        if entry_type == 0:
            # X509 entry: 3-byte length prefix then DER cert
            cert_len = int.from_bytes(leaf[12:15], "big")
            cert_der = leaf[15 : 15 + cert_len]
        elif entry_type == 1:
            # Precert entry: 32-byte issuer hash + 3-byte length + TBSCertificate
            # Skip for now, precerts are trickier to parse
            return []
        else:
            return []

        cert = x509.load_der_x509_certificate(cert_der)
        try:
            san = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            # Fall back to common name
            cn_attrs = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            return [attr.value for attr in cn_attrs] if cn_attrs else []

    except Exception:
        return []


def tail_log(log_info):
    """Continuously tail a single CT log, pushing discovered domains to Redis."""
    log_name = log_info["name"]
    log_url = log_info["url"]

    console.print(
        f"[bold green]📡 Connecting to CT log:[/bold green] {log_name}"
    )

    try:
        tree_size = get_tree_size(log_url)
    except Exception as e:
        console.print(f"[red]✗ Failed to connect to {log_name}: {e}[/red]")
        return

    # Start a bit behind the tip so we get an immediate backlog of certs
    cursor = tree_size - BACKLOG
    console.print(
        f"[dim]   Tree size: {tree_size:,} entries. Starting {BACKLOG} behind tip.[/dim]"
    )

    while True:
        try:
            current_size = get_tree_size(log_url)

            if cursor >= current_size:
                # No new entries yet, wait and poll again
                time.sleep(0.5)
                continue

            end = min(cursor + BATCH_SIZE - 1, current_size - 1)
            entries = fetch_entries(log_url, cursor, end)

            for entry in entries:
                domains = parse_domains(entry)
                for domain in domains:
                    if domain.startswith("*."):
                        domain = domain[2:]

                    console.print(
                        f"[bold green]✨ CT [{log_name}]:[/bold green] {domain}"
                    )
                    r.lpush("targets", domain)

            cursor = end + 1

        except KeyboardInterrupt:
            raise
        except Exception as e:
            console.print(
                f"[yellow]⚠ {log_name} poll error: {e}. Retrying...[/yellow]"
            )
            time.sleep(3)


def run_ct_stream():
    """Tail the first available CT log."""
    console.print(
        "[bold green][*] Starting CT Log poller (direct RFC 6962 API)...[/bold green]"
    )
    # Try each log until one works
    for log in CT_LOGS:
        try:
            tail_log(log)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            console.print(f"[red]✗ {log['name']} failed: {e}[/red]")
            continue


if __name__ == "__main__":
    run_ct_stream()
