import time
from datetime import datetime, timezone
from plyer import notification
from elasticsearch import Elasticsearch

# -------- CONFIG --------
ES_HOST = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS = "elastic passsword"
CHECK_INTERVAL = 30  # check every 30 seconds
# ------------------------

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))

print("[*] SOC Alert Monitor started...")
print("[*] Watching for new alerts...")

last_check = datetime.now(timezone.utc)

while True:
    try:
        # Search for new alerts
        query = {
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type": "alert"}},
                        {"range": {"@timestamp": {"gte": last_check.isoformat()}}}
                    ]
                }
            }
        }

        res = es.search(index="suricata-alerts-*", body=query)
        hits = res["hits"]["hits"]

        for hit in hits:
            src = hit["_source"]
            signature = src.get("alert", {}).get("signature", "Unknown Alert")
            src_ip = src.get("source", {}).get("ip", "Unknown")
            threat = src.get("threat_level", "LOW")
            
            # Show Windows notification
            notification.notify(
                title=f"🚨 SOC Alert - {threat}",
                message=f"Rule: {signature}\nFrom: {src_ip}",
                app_name="SOC Lab",
                timeout=10
            )
            print(f"[!] Alert: {signature} from {src_ip} - {threat}")

        # Also check Elastic Defend alerts
        query2 = {
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.kind": "alert"}},
                        {"range": {"@timestamp": {"gte": last_check.isoformat()}}}
                    ]
                }
            }
        }

        res2 = es.search(index=".alerts-security*", body=query2)
        hits2 = res2["hits"]["hits"]

        for hit in hits2:
            src = hit["_source"]
            rule_name = src.get("kibana.alert.rule.name", "Unknown Rule")
            severity = src.get("kibana.alert.severity", "unknown")
            host = src.get("host", {}).get("name", "Unknown Host")

            notification.notify(
                title=f"🛡️ Elastic Defend - {severity.upper()}",
                message=f"Rule: {rule_name}\nHost: {host}",
                app_name="SOC Lab",
                timeout=10
            )
            print(f"[!] Defend Alert: {rule_name} on {host} - {severity}")

        last_check = datetime.now(timezone.utc)

    except Exception as e:
        print(f"[!] Error: {e}")

    time.sleep(CHECK_INTERVAL)