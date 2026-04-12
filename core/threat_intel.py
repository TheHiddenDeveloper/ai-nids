"""
Threat Intelligence Manager
---------------------------
Handles GeoIP enrichment and suspicious IP reputation checks using community feeds.
Feeds:
- Emerging Threats (compromised hosts)
- Feodo Tracker (botnets/C2)
- ip-api.com (GeoIP)
"""

import requests
import json
import threading
import time
from loguru import logger
from core.redis_client import get_redis_client

class ThreatIntelManager:
    GEO_PREFIX = "nids:geo:cache"
    REP_PREFIX = "nids:rep:cache"
    BLOCKLIST_KEY = "nids:blocklist"
    GEO_TTL = 86400 * 30  # 30 days
    REP_TTL = 3600 * 12   # 12 hours
    
    FEEDS = {
        "emerging_threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    }

    def __init__(self):
        self.redis = get_redis_client()
        # Start background sync if not already running recently
        self._start_sync_thread()

    def _start_sync_thread(self):
        """Runs the blocklist update in a background thread."""
        thread = threading.Thread(target=self.sync_feeds, daemon=True)
        thread.start()

    def sync_feeds(self):
        """Downloads community feeds and populates Redis set."""
        if not self.redis:
            logger.warning("ThreatIntel: Redis not available for feed sync.")
            return

        # Check for recent sync to avoid hammering APIs
        last_sync = self.redis.get("nids:intel:last_sync")
        if last_sync and (time.time() - float(last_sync) < 3600):
            logger.debug("ThreatIntel: Recent sync found, skipping update.")
            return

        logger.info("ThreatIntel: Syncing community reputation feeds...")
        malicious_ips = set()

        for name, url in self.FEEDS.items():
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    lines = r.text.splitlines()
                    count = 0
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Some feeds have comments on same line
                        ip = line.split()[0]
                        malicious_ips.add(ip)
                        count += 1
                    logger.debug(f"ThreatIntel: Ingested {count} IPs from {name}")
            except Exception as e:
                logger.error(f"ThreatIntel: Failed to sync {name}: {e}")

        if malicious_ips:
            # Atomic update of the blocklist set
            temp_key = f"{self.BLOCKLIST_KEY}:temp"
            self.redis.delete(temp_key)
            # Add in chunks to avoid large command errors
            ip_list = list(malicious_ips)
            for i in range(0, len(ip_list), 1000):
                self.redis.sadd(temp_key, *ip_list[i:i+1000])
            
            self.redis.rename(temp_key, self.BLOCKLIST_KEY)
            self.redis.set("nids:intel:last_sync", time.time())
            logger.info(f"ThreatIntel: Blocklist updated with {len(malicious_ips)} unique entries.")

    def get_enrichment(self, ip: str) -> dict:
        """
        Combines GeoIP data and Reputation status.
        Returns: {lat, lon, country, city, isp, is_malicious, threat_level}
        """
        if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
            return {}

        result = self._get_geo(ip) or {}
        
        # Check reputation
        is_malicious = False
        if self.redis:
            is_malicious = bool(self.redis.sismember(self.BLOCKLIST_KEY, ip))
        
        result["is_malicious"] = is_malicious
        result["threat_level"] = "high" if is_malicious else "none"
        return result

    def _get_geo(self, ip: str) -> dict:
        """Internal: GeoIP with Redis caching."""
        if not self.redis:
            return self._query_geo_api(ip)

        try:
            cached = self.redis.get(f"{self.GEO_PREFIX}:{ip}")
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.warning(f"ThreatIntel: Geo cache check failed: {e}")

        data = self._query_geo_api(ip)
        if data and self.redis:
            try:
                self.redis.setex(f"{self.GEO_PREFIX}:{ip}", self.GEO_TTL, json.dumps(data))
            except Exception as e:
                logger.error(f"ThreatIntel: Geo cache save failed: {e}")
        return data

    def _query_geo_api(self, ip: str) -> dict:
        """Internal: Query free ip-api.com."""
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    return {
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "country": data.get("country"),
                        "countryCode": data.get("countryCode"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "asn": data.get("as")
                    }
            return None
        except Exception as e:
            logger.error(f"ThreatIntel: API Error: {e}")
            return None
