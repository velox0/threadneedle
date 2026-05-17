# Threat Infrastructure Graphing Stack

An internet-scale threat reconnaissance and infrastructure graphing pipeline. This stack listens to global Certificate Transparency (CT) logs in real-time, extracts newly discovered domains, performs various recon modules (TLS fingerprinting, ASN lookups, Nmap scans, Favicon hashing), and builds a continuously updating relationship graph in Neo4j.

## Architecture

* **Queue**: Redis
* **Graph DB**: Neo4j
* **Recon Handlers**: Python Workers
* **Virtual Environment**: `uv`

```text
       [Certificate Transparency Stream]
                      │
                (ct_stream.py)
            resolve domain to IP
                      │
                ┌─────▼─────┐
                │ Redis Q   │ (targets list)
                └─────┬─────┘
                      │
               ┌──────▼──────┐
               │  worker.py  │ ─── Nmap Scan
               └──────┬──────┘ ─── ASN Lookup (whois)
                      │        ─── TLS Fingerprint
                      │        ─── HTTP Headers & Title
                      │        ─── Favicon Hash (mmh3)
                ┌─────▼─────┐
                │   Neo4j   │
                └───────────┘
```

## Prerequisites

- **Docker** & **Docker Compose**
- **Python 3.10+** and [uv](https://github.com/astral-sh/uv)
- OS-level dependencies for the recon modules:
  - `nmap`
  - `whois`

## Setup

1. **Start the Infrastructure Components**
   Spin up Redis and Neo4j using Docker:
   ```bash
   docker compose up -d
   ```

2. **Initialize Python Environment**
   Create a virtual environment with `uv` and install dependencies:
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install -r requirements.txt
   ```

## Usage

You can run the recon stack in a few different ways depending on your needs.

### 1. Ingest via Certificate Transparency Logs
To start discovering domains from the global certificate stream (internet-scale):
```bash
# In Terminal 1: Start CT stream listener
python ct_stream.py

# In Terminal 2: Start the recon worker
python worker.py
```
*Note: The CT stream discovers hundreds of domains per second. Your graph will grow rapidly.*

### 2. Manual Seeding
If you prefer to feed specific IPs instead of the internet firehose:
```bash
# In Terminal 1: Add seed IPs to Redis
python seed.py

# In Terminal 2: Process the seeded IPs
python worker.py
```

## Graph Analysis

Access the Neo4j web interface at [http://localhost:7474](http://localhost:7474).
**Default Credentials**: `neo4j` / `password`

### Example Cypher Queries

**Shared Favicon Clusters** (Find distinct IPs sharing the same favicon hash):
```cypher
MATCH (a)-[:REL {type:"favicon_hash"}]->(f)<-[:REL {type:"favicon_hash"}]-(b)
WHERE a <> b
RETURN a, b, f
```

**Shared ASN + TLS Cipher** (Identify related infrastructure):
```cypher
MATCH (a)-[:REL {type:"hosted_on"}]->(asn)<-[:REL {type:"hosted_on"}]-(b)
MATCH (a)-[:REL {type:"tls_cipher"}]->(tls)<-[:REL {type:"tls_cipher"}]-(b)
WHERE a <> b
RETURN a,b,asn,tls
```

Alternatively, run the `pivots.py` script to execute predefined queries directly from the terminal:
```bash
python pivots.py
```
