import requests
from elasticsearch import Elasticsearch

# ---------------- CONFIG ----------------
ES_HOST = "http://localhost:9200"
INDEX = "suricata-alerts-*"
VT_API_KEY = "VT API key"
OTX_API_KEY = "OTX APi key"
ES_USER = "elastic"
ES_PASS = "elastic password"
# ---------------------------------------

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))

# -------- VIRUSTOTAL FUNCTIONS --------
def vt_check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            return {
                "malicious": attrs["last_analysis_stats"]["malicious"],
                "suspicious": attrs["last_analysis_stats"]["suspicious"],
                "harmless": attrs["last_analysis_stats"]["harmless"],
                "country": attrs.get("country", ""),
                "reputation": attrs.get("reputation", 0),
                "as_owner": attrs.get("as_owner", ""),
                "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
            }
        elif r.status_code == 429:
            print(f"[VT] Rate limit hit for {ip}")
    except Exception as e:
        print(f"[VT IP Error] {e}")
    return None

def vt_check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            return {
                "malicious": attrs["last_analysis_stats"]["malicious"],
                "suspicious": attrs["last_analysis_stats"]["suspicious"],
                "harmless": attrs["last_analysis_stats"]["harmless"],
                "reputation": attrs.get("reputation", 0),
                "link": f"https://www.virustotal.com/gui/domain/{domain}"
            }
        elif r.status_code == 429:
            print(f"[VT] Rate limit hit for {domain}")
    except Exception as e:
        print(f"[VT Domain Error] {e}")
    return None

def vt_check_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            return {
                "malicious": attrs["last_analysis_stats"]["malicious"],
                "suspicious": attrs["last_analysis_stats"]["suspicious"],
                "harmless": attrs["last_analysis_stats"]["harmless"],
                "file_name": attrs.get("meaningful_name", ""),
                "file_type": attrs.get("type_description", ""),
                "link": f"https://www.virustotal.com/gui/file/{hash_value}"
            }
        elif r.status_code == 429:
            print(f"[VT] Rate limit hit for {hash_value}")
    except Exception as e:
        print(f"[VT Hash Error] {e}")
    return None

# -------- OTX FUNCTIONS --------
def otx_check_ip(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "pulse_count": len(data.get("pulse_info", {}).get("pulses", [])),
                "country": data.get("country_name", ""),
                "asn": data.get("asn", ""),
                "link": f"https://otx.alienvault.com/indicator/ip/{ip}"
            }
    except Exception as e:
        print(f"[OTX IP Error] {e}")
    return None

def otx_check_domain(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "pulse_count": len(data.get("pulse_info", {}).get("pulses", [])),
                "link": f"https://otx.alienvault.com/indicator/domain/{domain}"
            }
    except Exception as e:
        print(f"[OTX Domain Error] {e}")
    return None

def otx_check_hash(hash_value):
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "pulse_count": len(data.get("pulse_info", {}).get("pulses", [])),
                "link": f"https://otx.alienvault.com/indicator/file/{hash_value}"
            }
    except Exception as e:
        print(f"[OTX Hash Error] {e}")
    return None

# -------- THREAT LEVEL CALCULATOR --------
def calculate_threat_level(vt_result, otx_result):
    malicious = 0
    pulses = 0
    if vt_result:
        malicious = vt_result.get("malicious", 0)
    if otx_result:
        pulses = otx_result.get("pulse_count", 0)
    if malicious >= 5 or pulses >= 3:
        return "HIGH"
    elif malicious >= 1 or pulses >= 1:
        return "MEDIUM"
    return "LOW"

# -------- MAIN ENRICHMENT LOOP --------
print("[*] Fetching recent alerts from Elasticsearch...")

query = {
    "size": 50,
    "query": {
        "bool": {
            "must": [
                {"term": {"event_type": "alert"}},
                {"range": {"@timestamp": {"gte": "now-1h"}}}
            ],
            "must_not": [
                {"exists": {"field": "enriched"}}
            ]
        }
    }
}

res = es.search(index=INDEX, body=query)
hits = res["hits"]["hits"]
print(f"[*] Found {len(hits)} unenriched alerts")

for hit in hits:
    doc_id = hit["_id"]
    doc_index = hit["_index"]
    src = hit["_source"]

    enrichment = {}

    # ---- IP enrichment ----
    src_ip = src.get("source", {}).get("ip")
    dest_ip = src.get("destination", {}).get("ip")

    # Skip private IPs
    import re
    private = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')

    if src_ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', src_ip) and not private.match(src_ip):
        print(f"[*] Checking source IP: {src_ip}")
        vt = vt_check_ip(src_ip)
        otx = otx_check_ip(src_ip)
        enrichment["src_ip_vt"] = vt
        enrichment["src_ip_otx"] = otx
        enrichment["src_threat_level"] = calculate_threat_level(vt, otx)
        if vt:
            print(f"    VT malicious: {vt['malicious']} | Link: {vt['link']}")
        if otx:
            print(f"    OTX pulses: {otx['pulse_count']} | Link: {otx['link']}")

    if dest_ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', dest_ip) and not private.match(dest_ip):
        print(f"[*] Checking destination IP: {dest_ip}")
        vt = vt_check_ip(dest_ip)
        otx = otx_check_ip(dest_ip)
        enrichment["dest_ip_vt"] = vt
        enrichment["dest_ip_otx"] = otx
        enrichment["dest_threat_level"] = calculate_threat_level(vt, otx)

    # ---- Domain enrichment ----
    domain = src.get("dns", {}).get("query", [{}])
    if isinstance(domain, list) and len(domain) > 0:
        domain = domain[0].get("rrname")
    else:
        domain = None

    if domain:
        print(f"[*] Checking domain: {domain}")
        vt = vt_check_domain(domain)
        otx = otx_check_domain(domain)
        enrichment["domain_vt"] = vt
        enrichment["domain_otx"] = otx
        enrichment["domain_threat_level"] = calculate_threat_level(vt, otx)

    # ---- File hash enrichment ----
    file_hash = src.get("fileinfo", {}).get("sha256")
    if file_hash:
        print(f"[*] Checking file hash: {file_hash}")
        vt = vt_check_hash(file_hash)
        otx = otx_check_hash(file_hash)
        enrichment["file_vt"] = vt
        enrichment["file_otx"] = otx
        enrichment["file_threat_level"] = calculate_threat_level(vt, otx)

    # ---- Update Elasticsearch ----
    if enrichment:
        enrichment["enriched"] = True
        try:
            es.update(index=doc_index, id=doc_id, body={"doc": enrichment})
            print(f"[+] Updated document {doc_id}")
        except Exception as e:
            print(f"[!] Failed to update {doc_id}: {e}")

print("\n[✓] Enrichment complete!")