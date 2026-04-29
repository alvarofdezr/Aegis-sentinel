import time
import httpx
import structlog
from typing import Tuple, Dict

logger = structlog.get_logger()

class AsyncThreatIntel:
    """Advanced Asynchronous Threat Intelligence engine.
    
    Includes an in-memory TTL cache to prevent API rate-limiting
    and ensure zero-latency verdicts for previously seen flows.
    """

    def __init__(self, api_key: str, cache_ttl_seconds: int = 3600):
        """
        Args:
            api_key: The API key for the external reputation service.
            cache_ttl_seconds: How long to remember an IP's reputation (default: 1 hour).
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl_seconds
        
        # Cache memory structure: { "ip_address": (is_malicious, expiration_timestamp) }
        self._cache: Dict[str, Tuple[bool, float]] = {}
        
        # Async HTTP client connection pool
        self._http_client = httpx.AsyncClient(timeout=2.0)

    async def is_malicious(self, ip_address: str) -> bool:
        """Evaluates if an IP address is malicious, using cache first."""
        
        # 1. Check local cache (Sub-millisecond latency)
        if ip_address in self._cache:
            is_bad, expire_time = self._cache[ip_address]
            if time.time() < expire_time:
                return is_bad
            else:
                # Cache expired, remove it
                del self._cache[ip_address]

        # 2. Whitelist bypass (Local IPs shouldn't be queried)
        if ip_address.startswith(("10.", "192.168.", "127.", "172.")):
            self._update_cache(ip_address, False)
            return False

        # 3. Network Query (Simulated/API placeholder)
        # Here we will integrate the real API (e.g., VirusTotal or custom backend)
        is_bad = await self._query_external_api(ip_address)
        
        # 4. Save result to cache
        self._update_cache(ip_address, is_bad)
        return is_bad

    def _update_cache(self, ip_address: str, is_malicious: bool) -> None:
        """Updates the internal TTL cache."""
        expiration = time.time() + self.cache_ttl
        self._cache[ip_address] = (is_malicious, expiration)
        
        if is_malicious:
            logger.warning("threat_intel_cache_updated", ip=ip_address, status="MALICIOUS")

    async def _query_external_api(self, ip_address: str) -> bool:
        """Makes the actual HTTP call to the reputation service."""
        if not self.api_key:
            logger.debug("threat_intel_no_key", msg="Skipping external query")
            return False

        try:
            # Placeholder for actual API call, e.g., AbuseIPDB
            # response = await self._http_client.get(
            #     "https://api.abuseipdb.com/api/v2/check",
            #     params={"ipAddress": ip_address},
            #     headers={"Key": self.api_key, "Accept": "application/json"}
            # )
            # data = response.json()
            # return data.get("data", {}).get("abuseConfidenceScore", 0) > 50
            
            # Simulated safe response for testing
            return False
            
        except httpx.RequestError as e:
            logger.error("threat_intel_api_error", error=str(e))
            # Fail-open: if the API is down, don't break the user's internet
            return False

    async def close(self) -> None:
        """Closes the async HTTP client gracefully."""
        await self._http_client.aclose()