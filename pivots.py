from neo4j import GraphDatabase

neo = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "password")
)

def query_shared_favicon_clusters():
    query = """
    MATCH (a)-[:REL {type:"favicon_hash"}]->(f)<-[:REL {type:"favicon_hash"}]-(b)
    WHERE a <> b
    RETURN a.value AS ip1, b.value AS ip2, f.value AS favicon_hash
    """
    with neo.session() as s:
        result = s.run(query)
        for record in result:
            print(f"Shared Favicon: {record['ip1']} <--> {record['ip2']} (Hash: {record['favicon_hash']})")

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
            print(f"Shared ASN & TLS: {record['ip1']} <--> {record['ip2']} (ASN: {record['asn']}, TLS: {record['tls']})")

if __name__ == "__main__":
    print("--- Shared Favicon Clusters ---")
    query_shared_favicon_clusters()
    print("\\n--- Shared ASN + TLS ---")
    query_shared_asn_tls()
