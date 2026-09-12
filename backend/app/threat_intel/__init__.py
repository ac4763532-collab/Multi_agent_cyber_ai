"""Threat Intelligence Engine - Provider-independent threat intelligence."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class IndicatorType(StrEnum):
    """Types of threat indicators."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CVE = "cve"
    HOSTNAME = "hostname"
    EMAIL = "email"


class ThreatReputation(StrEnum):
    """Reputation levels for indicators."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    BENIGN = "benign"


class IntelligenceResult(BaseModel):
    """Result from threat intelligence lookup."""

    indicator: str
    indicator_type: IndicatorType
    source: str
    reputation: ThreatReputation = ThreatReputation.UNKNOWN
    confidence: float = 0.0  # 0-1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    retrieval_time: datetime = Field(default_factory=utc_now)
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_types: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False


class ThreatIntelProvider(ABC):
    """Abstract base for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

    @abstractmethod
    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> IntelligenceResult | None:
        """Look up an indicator."""
        pass

    async def lookup_batch(
        self, indicators: list[tuple[str, IndicatorType]]
    ) -> list[IntelligenceResult]:
        """Look up multiple indicators."""
        results = []
        for indicator, ind_type in indicators:
            result = await self.lookup(indicator, ind_type)
            if result:
                results.append(result)
        return results


class MockThreatIntelProvider(ThreatIntelProvider):
    """Mock provider for testing."""

    # Known malicious indicators for testing
    MALICIOUS_IPS = {
        "185.220.101.1": {"reputation": "malicious", "tags": ["tor_exit", "scanner"]},
        "45.33.32.156": {"reputation": "malicious", "tags": ["c2", "emotet"]},
        "192.168.1.1": {"reputation": "benign", "tags": ["private"]},
    }

    MALICIOUS_DOMAINS = {
        "evil.com": {"reputation": "malicious", "tags": ["phishing", "malware"]},
        "malware-c2.tk": {"reputation": "malicious", "tags": ["c2", "apt"]},
        "suspicious-login.ml": {"reputation": "suspicious", "tags": ["phishing"]},
    }

    MALICIOUS_HASHES = {
        "44d88612fea8a8f36de82e1278abb02f": {
            "reputation": "malicious",
            "malware": ["eicar_test"],
        },
        "e99a18c428cb38d5f260853678922e03": {
            "reputation": "malicious",
            "malware": ["emotet"],
        },
    }

    @property
    def name(self) -> str:
        return "mock_provider"

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType
    ) -> IntelligenceResult | None:
        """Look up indicator in mock database."""
        result = IntelligenceResult(
            indicator=indicator,
            indicator_type=indicator_type,
            source=self.name,
        )

        indicator_lower = indicator.lower()

        if indicator_type == IndicatorType.IP:
            if indicator in self.MALICIOUS_IPS:
                data = self.MALICIOUS_IPS[indicator]
                result.reputation = ThreatReputation(data["reputation"])
                result.tags = data.get("tags", [])
                result.confidence = 0.9
                result.first_seen = utc_now() - timedelta(days=30)
                result.last_seen = utc_now() - timedelta(hours=1)

        elif indicator_type == IndicatorType.DOMAIN:
            if indicator_lower in self.MALICIOUS_DOMAINS:
                data = self.MALICIOUS_DOMAINS[indicator_lower]
                result.reputation = ThreatReputation(data["reputation"])
                result.tags = data.get("tags", [])
                result.confidence = 0.85
                result.first_seen = utc_now() - timedelta(days=14)
                result.last_seen = utc_now() - timedelta(hours=6)

        elif indicator_type in (
            IndicatorType.HASH_MD5,
            IndicatorType.HASH_SHA1,
            IndicatorType.HASH_SHA256,
        ):
            if indicator_lower in self.MALICIOUS_HASHES:
                data = self.MALICIOUS_HASHES[indicator_lower]
                result.reputation = ThreatReputation(data["reputation"])
                result.malware_families = data.get("malware", [])
                result.confidence = 0.95
                result.first_seen = utc_now() - timedelta(days=60)
                result.last_seen = utc_now() - timedelta(days=1)

        return result


class IntelligenceCache:
    """Cache for threat intelligence results."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[IntelligenceResult, datetime]] = {}

    def _key(self, indicator: str, indicator_type: IndicatorType) -> str:
        """Generate cache key."""
        return f"{indicator_type.value}:{indicator.lower()}"

    def get(
        self, indicator: str, indicator_type: IndicatorType
    ) -> IntelligenceResult | None:
        """Get cached result."""
        key = self._key(indicator, indicator_type)
        if key in self._cache:
            result, cached_at = self._cache[key]
            if (utc_now() - cached_at).total_seconds() < self.ttl:
                result.cached = True
                return result
            else:
                del self._cache[key]
        return None

    def set(self, result: IntelligenceResult) -> None:
        """Cache a result."""
        key = self._key(result.indicator, result.indicator_type)
        self._cache[key] = (result, utc_now())

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Number of cached items."""
        return len(self._cache)


class ThreatIntelligenceEngine:
    """Main threat intelligence engine with multiple providers."""

    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache_ttl: int = 3600,
    ):
        self.providers = providers or [MockThreatIntelProvider()]
        self.cache = IntelligenceCache(ttl_seconds=cache_ttl)
        self._lookup_count = 0

    def register_provider(self, provider: ThreatIntelProvider) -> None:
        """Register a new provider."""
        self.providers.append(provider)

    async def lookup(
        self,
        indicator: str,
        indicator_type: IndicatorType | None = None,
    ) -> list[IntelligenceResult]:
        """Look up an indicator across all providers."""
        # Auto-detect indicator type if not provided
        if indicator_type is None:
            indicator_type = self._detect_type(indicator)

        # Check cache first
        cached = self.cache.get(indicator, indicator_type)
        if cached:
            return [cached]

        # Query all providers
        results: list[IntelligenceResult] = []
        for provider in self.providers:
            try:
                result = await provider.lookup(indicator, indicator_type)
                if result:
                    results.append(result)
                    self.cache.set(result)
            except Exception:  # noqa: S110
                # Log error but continue with other providers
                pass

        self._lookup_count += 1
        return results

    async def lookup_batch(
        self, indicators: list[str]
    ) -> dict[str, list[IntelligenceResult]]:
        """Look up multiple indicators."""
        results: dict[str, list[IntelligenceResult]] = {}
        for indicator in indicators:
            results[indicator] = await self.lookup(indicator)
        return results

    async def enrich_event(
        self, event: dict[str, Any]
    ) -> dict[str, list[IntelligenceResult]]:
        """Enrich an event with threat intelligence."""
        enrichments: dict[str, list[IntelligenceResult]] = {}

        # Extract indicators from event
        indicators = self._extract_indicators(event)

        for indicator, ind_type in indicators:
            results = await self.lookup(indicator, ind_type)
            if results:
                enrichments[indicator] = results

        return enrichments

    def _detect_type(self, indicator: str) -> IndicatorType:
        """Auto-detect indicator type."""
        import re

        # IP address
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, indicator):
            return IndicatorType.IP

        # Hash patterns
        if re.match(r"^[a-fA-F0-9]{32}$", indicator):
            return IndicatorType.HASH_MD5
        if re.match(r"^[a-fA-F0-9]{40}$", indicator):
            return IndicatorType.HASH_SHA1
        if re.match(r"^[a-fA-F0-9]{64}$", indicator):
            return IndicatorType.HASH_SHA256

        # CVE
        if re.match(r"^CVE-\d{4}-\d+$", indicator, re.IGNORECASE):
            return IndicatorType.CVE

        # Email
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", indicator):
            return IndicatorType.EMAIL

        # URL
        if indicator.startswith(("http://", "https://")):
            return IndicatorType.URL

        # Default to domain
        return IndicatorType.DOMAIN

    def _extract_indicators(
        self, event: dict[str, Any]
    ) -> list[tuple[str, IndicatorType]]:
        """Extract indicators from an event."""
        indicators: list[tuple[str, IndicatorType]] = []

        # IP addresses
        for field in ["source_ip", "src_ip", "destination_ip", "dest_ip", "ip"]:
            if field in event and event[field]:
                indicators.append((event[field], IndicatorType.IP))

        # Domains
        for field in ["domain", "hostname", "host"]:
            if field in event and event[field]:
                indicators.append((event[field], IndicatorType.DOMAIN))

        # URLs
        for field in ["url", "uri"]:
            if field in event and event[field]:
                indicators.append((event[field], IndicatorType.URL))

        # Hashes
        for field in ["md5", "sha1", "sha256", "file_hash", "hash"]:
            if field in event and event[field]:
                value = event[field]
                ind_type = self._detect_type(value)
                indicators.append((value, ind_type))

        return indicators

    def get_aggregated_reputation(
        self, results: list[IntelligenceResult]
    ) -> ThreatReputation:
        """Get aggregated reputation from multiple results."""
        if not results:
            return ThreatReputation.UNKNOWN

        # Prioritize by severity
        for rep in [
            ThreatReputation.MALICIOUS,
            ThreatReputation.SUSPICIOUS,
            ThreatReputation.BENIGN,
        ]:
            if any(r.reputation == rep for r in results):
                return rep

        return ThreatReputation.UNKNOWN

    def get_metrics(self) -> dict[str, Any]:
        """Get engine metrics."""
        return {
            "providers": [p.name for p in self.providers],
            "provider_count": len(self.providers),
            "cache_size": self.cache.size,
            "total_lookups": self._lookup_count,
        }


# Singleton instance
_engine_instance: ThreatIntelligenceEngine | None = None


def get_threat_intel_engine() -> ThreatIntelligenceEngine:
    """Get threat intelligence engine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ThreatIntelligenceEngine()
    return _engine_instance
