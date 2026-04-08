import requests
import json
from loguru import logger
from core.redis_client import get_redis_client

class GeoLookup:
    """
    Resolves IP addresses to geographical coordinates with Redis caching.
    Uses the free ip-api.com service (limit 45 req/min).
    """
    CACHE_PREFIX = "nids:geo:cache"
    TTL = 86400 * 30  # 30 days

    def __init__(self):
        self.redis = get_redis_client()

    def get_location(self, ip: str):
        """Fetches Lat/Lon/Country/City for an IP, with caching."""
        if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
            return None

        # Check Redis cache first
        if self.redis:
            try:
                cached = self.redis.get(f"{self.CACHE_PREFIX}:{ip}")
                if cached:
                    return json.loads(cached)
            except Exception as e:
                logger.warning(f"GeoLookup: Cache check failed: {e}")

        # Web API Lookup (ip-api.com)
        try:
            logger.debug(f"GeoLookup: Querying API for {ip}")
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    loc = {
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp")
                    }
                    
                    # Store in Redis
                    if self.redis:
                        try:
                            self.redis.setex(f"{self.CACHE_PREFIX}:{ip}", self.TTL, json.dumps(loc))
                        except Exception as e:
                            logger.error(f"GeoLookup: Cache save failed: {e}")
                    
                    return loc
            return None
        except Exception as e:
            logger.error(f"GeoLookup API Error: {e}")
            return None

if __name__ == "__main__":
    # Quick test
    geo = GeoLookup()
    print(f"8.8.8.8: {geo.get_location('8.8.8.8')}")
