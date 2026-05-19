from neo4j import GraphDatabase

neo = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))


def query_shared_favicon_clusters():
    query = """
    MATCH (a)-[:REL {type:"favicon_hash"}]->(f)<-[:REL {type:"favicon_hash"}]-(b)
    WHERE a <> b
    RETURN a.value AS ip1, b.value AS ip2, f.value AS favicon_hash
    """
    with neo.session() as s:
        result = s.run(query)
        for record in result:
            print(
                f"Shared Favicon: {record['ip1']} <--> {record['ip2']} (Hash: {record['favicon_hash']})"
            )


def query_shared_asn_tls():
    query = """
    MATCH (a)-[:REL {type:"hosted_on"}]->(asn)<-[:REL {type:"hosted_on"}]-(b)
    MATCH (a)-[:REL {type:"tls_cipher"}]->(tls)<-[:REL {type:"tls_cipher"}]-(b)
    WHERE a <> b
    RETURN a.value AS ip1, b.value AS ip2, asn.value AS asn, tls.value AS tls
    """
    with neo.session() as s:
        result = s.run(query)
        for record in result:
            print(
                f"Shared ASN & TLS: {record['ip1']} <--> {record['ip2']} (ASN: {record['asn']}, TLS: {record['tls']})"
            )


def query_internet_map():
    # This query maps out macro-clusters of the internet based on our recon data:
    # Grouping domains and IPs by Organization (Provider) + ASN
    query = """
MATCH (domain:Entity {type: 'domain'})-[:REL {type: 'resolves_to'}]->(ip:Entity {type: 'ip'})
MATCH (ip)-[:REL {type: 'hosted_by'}]->(org:Entity {type: 'org'})
MATCH (ip)-[:REL {type: 'hosted_on'}]->(asn:Entity {type: 'asn'})
RETURN org.value AS provider, asn.value AS asn,
        count(DISTINCT ip.value) AS ip_count, collect(DISTINCT domain.value) AS domains
ORDER BY ip_count DESC
LIMIT 20
    """
    with neo.session() as s:
        result = s.run(query)
        for record in result:
            domains = ", ".join(record["domains"][:5])
            more = "..." if len(record["domains"]) > 5 else ""
            print(f"📍 {record['provider']} [ASN: {record['asn']}]")
            print(f"   => {record['ip_count']} IPs powering domains: {domains}{more}\n")


def find_undeclared_c2_infrastructure(known_malicious_ip):
    query = """
    MATCH (bad_ip:Entity {type: 'ip', value: $ip})-[r1:REL]->(fingerprint)<-[r2:REL]-(suspect_ip:Entity {type: 'ip'})
    WHERE r1.type IN ["favicon_hash", "tls_cipher"] AND r2.type = r1.type AND bad_ip <> suspect_ip
    MATCH (domain:Entity {type: 'domain'})-[:REL {type: 'resolves_to'}]->(suspect_ip)
    RETURN DISTINCT domain.value AS SuspiciousDomain, suspect_ip.value AS SuspectIP, fingerprint.value AS SharedFingerprint, r1.type AS MatchType
    """
    with neo.session() as s:
        result = s.run(query, ip=known_malicious_ip)
        found = False
        for record in result:
            found = True
            print(
                f"🚨 Suspicious Domain: {record['SuspiciousDomain']} -> {record['SuspectIP']} (Shared {record['MatchType']}: {record['SharedFingerprint']})"
            )
        if not found:
            print(f"No linked infrastructure found for {known_malicious_ip}.")


def find_campaign_clusters():
    # Finds fingerprints that are shared across MULTIPLE DIFFERENT domains.
    # This filters out load balancers (same domain, multiple IPs) and zones in on
    # campaigns where an actor hosts 5+ different domains using the same kit/server setup.
    query = """
    MATCH (domain:Entity {type: 'domain'})-[:REL {type: 'resolves_to'}]->(ip:Entity {type: 'ip'})-[r1:REL]->(fingerprint)
    WHERE r1.type IN ["favicon_hash", "tls_cipher"]
    WITH fingerprint, r1.type AS type, collect(DISTINCT domain.value) as domains, count(DISTINCT domain.value) as domain_count
    WHERE domain_count > 1
    RETURN fingerprint.value AS fingerprint, type, domain_count, domains
    ORDER BY domain_count DESC
    LIMIT 10
    """
    with neo.session() as s:
        result = s.run(query)
        for record in result:
            domains = ", ".join(record["domains"][:5])
            more = "..." if record["domain_count"] > 5 else ""
            print(f"🕵️  Shared {record['type']}: {record['fingerprint']}")
            print(f"   => {record['domain_count']} UNIQUE domains: {domains}{more}\n")


def find_dense_infrastructure_clusters():
    # Finds highly connected clusters where multiple domains resolve to multiple shared IPs.
    # High edge density between distinct domains and IPs indicates strongly linked infrastructure.
    query = """
        MATCH (d1:Entity {type: 'domain'})
            -[:REL {type: 'resolves_to'}]->
            (ip:Entity {type: 'ip'})
            <-[:REL {type: 'resolves_to'}]-
            (d2:Entity {type: 'domain'})
        WHERE d1.value < d2.value
        WITH
            d1,
            d2,
            count(DISTINCT ip) AS shared_ips_count,
            collect(DISTINCT ip.value) AS shared_ips
        WHERE shared_ips_count > 1
        RETURN
            d1.value AS domain1,
            d2.value AS domain2,
            shared_ips_count,
            shared_ips
        ORDER BY shared_ips_count DESC
        LIMIT 10
    """
    with neo.session() as s:
        result = s.run(query)
        for record in result:
            ips = ", ".join(record["shared_ips"][:5])
            more = "..." if record["shared_ips_count"] > 5 else ""
            print(
                f"🔗 Strongly Linked Pair: {record['domain1']} <--> {record['domain2']}"
            )
            print(f"   => Shared {record['shared_ips_count']} IPs: {ips}{more}")


if __name__ == "__main__":
    print("\n--- Internet Infrastructure Map ---")
    query_internet_map()
    print("\n--- Shared Favicon Clusters ---")
    query_shared_favicon_clusters()
    print("\n--- Shared ASN + TLS ---")
    query_shared_asn_tls()
    print("\n--- C2 Infrastructure Hunt ---")
    find_undeclared_c2_infrastructure("112.213.108.245")
    print("\n--- Threat Campaign Clusters (Distinct Domains) ---")
    find_campaign_clusters()
    print("\n--- Dense Infrastructure Clusters (Strongly Linked) ---")
    find_dense_infrastructure_clusters()
