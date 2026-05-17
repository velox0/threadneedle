# Threat Infrastructure Graphing Stack

An internet-scale threat reconnaissance and infrastructure graphing pipeline. This stack discovers domains from global Certificate Transparency logs in real-time, resolves them, fingerprints the underlying infrastructure, and builds a continuously updating relationship graph in Neo4j for cluster analysis.

---

## Architecture Overview

```text
       ┌──────────────────────────────┐
       │  Google CT Log Servers       │
       │  (Argon 2025h1/h2, Xenon)   │
       │  RFC 6962 HTTP API           │
       └──────────────┬───────────────┘
                      │ HTTP polling (256 entries/batch)
                      │
              ┌───────▼───────┐
              │  ct_stream.py │  Parse X.509 certs → extract domains
              └───────┬───────┘
                      │ LPUSH domain names
                      │
              ┌───────▼───────┐
              │  Redis Queue  │  Key: "targets" (list)
              └───────┬───────┘
                      │ BRPOP (blocking pop)
          ┌───────────┼───────────┐
          │           │           │
   ┌──────▼──┐ ┌─────▼───┐ ┌────▼────┐
   │Worker 1 │ │Worker 2 │ │Worker 3 │   (parallel multiprocessing)
   └────┬────┘ └────┬────┘ └────┬────┘
        │           │           │
        │  For each target:     │
        │  ├─ DNS Resolution    │
        │  ├─ WHOIS → ASN      │
        │  ├─ TLS Handshake     │
        │  ├─ Favicon mmh3 Hash │
        │  ├─ HTTP Headers      │
        │  └─ Nmap Top 20 Ports │
        │           │           │
        └───────────┼───────────┘
                    │ MERGE (upsert)
            ┌───────▼───────┐
            │    Neo4j      │  Graph database
            │  (bolt:7687)  │  UI at :7474
            └───────────────┘
```

---

## How Each Component Works

### 1. `main.py` — The Supervisor

This is the only script you run. It uses Python's `multiprocessing` module to spawn:

- **1 CT Stream process** — polls Certificate Transparency logs
- **3 Worker processes** — consume the Redis queue in parallel

All processes are managed together. `Ctrl+C` triggers a clean shutdown of every child process.

### 2. `ct_stream.py` — Certificate Transparency Poller

Instead of relying on third-party websocket services (like certstream, which is frequently down), we **poll Google's CT log servers directly** using the [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) HTTP API.

#### What are CT Logs?

Certificate Transparency is a global, append-only public ledger of every TLS certificate issued by a trusted Certificate Authority. Every CA (Let's Encrypt, DigiCert, Cloudflare, etc.) is **required** to submit certificates here before browsers will trust them.

#### How the poller works:

1. **`get-sth`** (Signed Tree Head) — Asks the log server "how many total entries exist?" This returns the `tree_size`.
2. **Start position** — We begin `BACKLOG` (500) entries before the tip, giving us an immediate batch of data to process.
3. **`get-entries`** — Fetches up to 256 raw certificate entries per request.
4. **Parse X.509** — Each entry contains a DER-encoded certificate. We decode it using the `cryptography` library and extract:
   - **SAN** (Subject Alternative Name) — the list of all domains the cert covers
   - **CN** (Common Name) — fallback if no SAN exists
5. **Strip wildcards** — `*.example.com` becomes `example.com`
6. **Push to Redis** — Each domain is `LPUSH`ed into the `"targets"` list for workers to consume.
7. **Loop** — Once caught up, the poller checks for new entries every 0.5 seconds.

#### Failover

Three CT log endpoints are configured. If one fails, the poller automatically falls through to the next:

- Google Argon 2025h1 (US)
- Google Argon 2025h2 (US)
- Google Xenon 2025h1 (EU)

### 3. `worker.py` — The Recon Engine

Each worker process runs an infinite loop, blocking on `BRPOP` until a target appears in Redis. When a target arrives, the worker runs **6 recon modules** against it:

#### Module 1: DNS Resolution

```
Domain → IP address
```

If the target from the CT stream is a domain name (not an IP), the worker resolves it via `socket.gethostbyname()`. The `(domain) -[resolves_to]→ (ip)` relationship is written to Neo4j. If resolution fails, the target is silently dropped.

#### Module 2: ASN Lookup

```
IP → Autonomous System Number
```

Runs the system `whois` command against the IP and parses the output for the `origin` field. This identifies which network operator hosts the IP (e.g., `AS13335` = Cloudflare, `AS15169` = Google).

**Graph edge:** `(ip) -[hosted_on]→ (asn)`

#### Module 3: TLS Fingerprint

```
IP:443 → cipher suite + certificate issuer
```

Opens a raw SSL socket to port 443, performs a TLS handshake, and extracts:

- The negotiated **cipher suite** (e.g., `TLS_AES_256_GCM_SHA384`)
- The certificate **issuer** chain

Threat actors often reuse the same TLS configuration across their infrastructure. Shared cipher suites are a strong clustering signal.

**Graph edge:** `(ip) -[tls_cipher]→ (cipher)`

#### Module 4: Favicon Hash

```
IP → mmh3 hash of /favicon.ico
```

Fetches `http(s)://<ip>/favicon.ico` and computes its [MurmurHash3](https://en.wikipedia.org/wiki/MurmurHash). This is the same technique used by [Shodan](https://www.shodan.io/) for favicon-based infrastructure discovery. Identical favicon hashes across different IPs strongly suggest shared infrastructure or the same web application deployment.

**Graph edge:** `(ip) -[favicon_hash]→ (hash)`

#### Module 5: HTTP Fingerprint

```
IP → Server header value
```

Makes a simple `GET /` request and extracts the `Server` response header (e.g., `nginx`, `cloudflare`, `Apache/2.4.41`). This identifies the web server software.

**Graph edge:** `(ip) -[server]→ (server_name)`

#### Module 6: Nmap Port Scan

```
IP → open ports + service versions
```

Runs `nmap -Pn -sV --top-ports 20` to identify the top 20 most common open ports and their service versions. The output is parsed to extract only the open ports for clean display.

> [!NOTE]
> Nmap is the slowest module by far (up to 60+ seconds per host for service detection). This is why we run 3 workers in parallel.

### 4. `pivots.py` — Cluster Analysis Queries

Pre-built Cypher queries for finding infrastructure clusters:

- **Shared Favicon Clusters** — Find IPs that serve the same favicon (likely same operator)
- **Shared ASN + TLS** — Find IPs on the same network using the same TLS configuration (high confidence clustering)

### 5. `seed.py` — Manual Target Injection

Pushes hardcoded IPs directly into the Redis queue, bypassing the CT stream entirely. Useful for targeted investigations.

---

## Neo4j Graph Schema

All data is stored as a single node type (`Entity`) with relationships between them:

```
(:Entity {value, type})  -[:REL {type}]→  (:Entity {value, type})
```

| Node Type | Example `value`                   | Description                 |
| --------- | --------------------------------- | --------------------------- |
| `ip`      | `172.67.189.133`                  | An IPv4 address             |
| `domain`  | `example.com`                     | A domain name from CT logs  |
| `asn`     | `origin: AS13335`                 | Autonomous System Number    |
| `tls`     | `('TLS_AES_256_GCM_SHA384', ...)` | Negotiated TLS cipher suite |
| `favicon` | `277325061`                       | MurmurHash3 of favicon.ico  |
| `http`    | `cloudflare`                      | HTTP Server header value    |

| Relationship   | Meaning                     |
| -------------- | --------------------------- |
| `resolves_to`  | Domain → IP (DNS)           |
| `hosted_on`    | IP → ASN (network operator) |
| `tls_cipher`   | IP → TLS cipher suite       |
| `favicon_hash` | IP → favicon mmh3 hash      |
| `server`       | IP → HTTP server software   |

---

## Deduplication & Rescan Mode

### Deduplication (default)

Every IP that gets fully scanned is added to a Redis set (`processed`). On subsequent runs:

- **CT stream** skips domains whose IPs are already in the set
- **Workers** skip IPs already in the set

This means you can freely stop and restart the stack without wasting time re-scanning the same hosts. The graph data in Neo4j is preserved, and only new, unseen targets get processed.

### Rescan Mode (`--rescan`)

To check whether previously scanned infrastructure has changed (e.g., an IP moved to a different ASN, swapped TLS ciphers, or changed its HTTP server), run:

```bash
python main.py --rescan
```

This will:

1. Pull every IP from the `processed` set
2. Re-queue them all into Redis
3. For each IP, query Neo4j for existing data **before** scanning
4. Run all recon modules again
5. Compare old vs new values and report any differences
6. Auto-exit when the queue is drained

#### Example output

```
🔄 Re-scanning: 172.67.189.133
   ⚠ CHANGE [HTTP Server]
      old: nginx
      new: cloudflare
   ⚠ CHANGE [ASN]
      old: origin: AS15169
      new: origin: AS13335
   ⚡ 2 change(s) detected!

🔄 Re-scanning: 8.8.8.8
   ✓ No changes detected
```

### CLI Flags

| Flag              | Description                                     |
| ----------------- | ----------------------------------------------- |
| `--rescan`        | Re-scan all known targets for changes           |
| `--workers N`     | Number of parallel worker processes (default: 3) |

---

## Quick Start

```bash
# 1. Start Redis + Neo4j
docker compose up -d

# 2. Setup Python environment
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt

# 3. Run the full stack (CT stream + 3 workers)
python main.py

# 4. Open Neo4j UI
open http://localhost:7474
# Login: neo4j / password

# 5. Later — check for infrastructure changes
python main.py --rescan
```

## File Map

| File                 | Purpose                                               |
| -------------------- | ----------------------------------------------------- |
| `main.py`            | Supervisor — spawns all processes, run this           |
| `ct_stream.py`       | Polls CT logs, discovers domains, feeds Redis         |
| `worker.py`          | Consumes Redis, runs 6 recon modules, writes to Neo4j |
| `pivots.py`          | Pre-built Cypher queries for cluster analysis         |
| `seed.py`            | Manually inject IPs into the queue                    |
| `docker-compose.yml` | Redis + Neo4j containers                              |
| `requirements.txt`   | Python dependencies                                   |
