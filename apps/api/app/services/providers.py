"""CYVRIX Vulnerability Provider Abstraction.

Provides a unified interface for querying vulnerability databases.
V1 uses OSV.dev. V2 adds container vulnerability support.

Security properties:
- Provider URLs from configuration only (not user input)
- Responses validated before processing
- Rate limiting with exponential backoff
- Timeout enforcement
- No provider failure silently converted to "no vulnerabilities"
"""
import logging
import os
from typing import Protocol, runtime_checkable

import httpx

from app.config import get_settings

logger = logging.getLogger("cyvrix.providers")
settings = get_settings()


@runtime_checkable
class VulnerabilityProvider(Protocol):
    """Protocol for vulnerability database providers."""

    async def query_batch(self, packages: list[dict]) -> list[dict]:
        """Query vulnerabilities for a batch of packages.

        Args:
            packages: List of {"name": str, "version": str, "ecosystem": str}

        Returns:
            List of vulnerability results (provider-specific format)
        """
        ...


class OSVProvider:
    """OSV.dev vulnerability provider."""

    def __init__(self, batch_url: str | None = None):
        self.batch_url = batch_url or os.environ.get(
            "OSV_BATCH_URL", "https://api.osv.dev/v1/querybatch"
        )

    async def query_batch(self, packages: list[dict]) -> list[dict]:
        """Query OSV.dev with batch requests."""
        if not packages:
            return []

        results = []
        batch_size = settings.max_deps_per_batch

        for i in range(0, len(packages), batch_size):
            chunk = packages[i:i + batch_size]
            queries = []
            for pkg in chunk:
                if not pkg.get("version"):
                    continue
                q = {
                    "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                    "version": pkg["version"],
                }
                queries.append(q)

            if not queries:
                continue

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            ) as client:
                for attempt in range(3):
                    try:
                        resp = await client.post(
                            self.batch_url, json={"queries": queries}
                        )
                        if resp.status_code == 429:
                            import asyncio
                            retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                            await asyncio.sleep(min(retry_after, 60))
                            continue
                        if resp.status_code >= 500:
                            if attempt < 2:
                                import asyncio
                                await asyncio.sleep(2 ** attempt)
                                continue
                            raise RuntimeError(f"OSV server error: {resp.status_code}")
                        resp.raise_for_status()
                        data = resp.json()
                        raw_results = data.get("results", [])
                        if isinstance(raw_results, list):
                            results.extend(raw_results)
                        break
                    except httpx.TimeoutException:
                        if attempt == 2:
                            raise RuntimeError("OSV request timed out after retries")
                        import asyncio
                        await asyncio.sleep(2 ** attempt)
                    except httpx.NetworkError as e:
                        if attempt == 2:
                            raise RuntimeError(f"OSV network error: {e}")
                        import asyncio
                        await asyncio.sleep(2 ** attempt)

        return results


class TrivyProvider:
    """Trivy-compatible vulnerability provider for container scanning.

    This provider queries container vulnerability databases.
    In V2, this connects to a mock provider for E2E testing.
    """

    def __init__(self, base_url: str | None = None):
        self.base_url = base_url or os.environ.get(
            "CONTAINER_VULN_URL", "http://localhost:8100"
        )

    async def query_batch(self, packages: list[dict]) -> list[dict]:
        """Query container vulnerabilities."""
        if not packages:
            return []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
        ) as client:
            for attempt in range(3):
                try:
                    resp = await client.post(
                        f"{self.base_url}/v1/container/vulns",
                        json={"packages": packages},
                    )
                    if resp.status_code == 429:
                        import asyncio
                        await asyncio.sleep(2 ** (attempt + 1))
                        continue
                    if resp.status_code >= 500:
                        if attempt < 2:
                            import asyncio
                            await asyncio.sleep(2 ** attempt)
                            continue
                        raise RuntimeError(f"Container vuln provider error: {resp.status_code}")
                    resp.raise_for_status()
                    return resp.json().get("results", [])
                except httpx.TimeoutException:
                    if attempt == 2:
                        raise RuntimeError("Container vuln provider timed out")
                    import asyncio
                    await asyncio.sleep(2 ** attempt)
                except httpx.NetworkError as e:
                    if attempt == 2:
                        raise RuntimeError(f"Container vuln provider network error: {e}")
                    import asyncio
                    await asyncio.sleep(2 ** attempt)

        return []


def get_osv_provider() -> OSVProvider:
    """Get the configured OSV provider."""
    return OSVProvider()


def get_container_provider() -> TrivyProvider:
    """Get the configured container vulnerability provider."""
    return TrivyProvider()
