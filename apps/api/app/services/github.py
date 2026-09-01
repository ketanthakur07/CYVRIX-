import os
import time
import httpx
import jwt
from typing import Optional
from app.config import get_settings

settings = get_settings()

GITHUB_API = os.environ.get("GITHUB_API_BASE", "https://api.github.com")


class GitHubAuthError(Exception):
    """Raised when GitHub authentication fails (401/403)."""
    pass


class GitHubRateLimitError(Exception):
    """Raised when GitHub rate limit is hit."""
    pass


class GitHubUnavailableError(Exception):
    """Raised when GitHub API is unavailable (5xx / network)."""
    pass


def _create_jwt() -> str:
    """Create a short-lived JWT for GitHub App authentication."""
    if not settings.github_app_id or not settings.github_app_private_key:
        raise GitHubAuthError(
            "GitHub App credentials not configured. "
            "Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY in your environment."
        )
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,  # 10 minutes
        "iss": settings.github_app_id,
    }
    return jwt.encode(payload, settings.github_app_private_key, algorithm="RS256")


async def get_installation_access_token(installation_id: int) -> str:
    """Generate a short-lived installation access token. Never persisted.

    Retries up to 3 times with exponential backoff on transient errors.
    Raises GitHubAuthError on 401/403 and GitHubUnavailableError on 5xx/network.
    """
    jwt_token = _create_jwt()
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(
                    f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
                    headers=headers,
                )
                if resp.status_code in (401, 403):
                    raise GitHubAuthError(
                        f"GitHub authentication failed for installation {installation_id} "
                        f"(HTTP {resp.status_code}). The App may have been revoked."
                    )
                resp.raise_for_status()
                return resp.json()["token"]
            except GitHubAuthError:
                raise
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403 and e.response.headers.get("X-RateLimit-Remaining") == "0":
                    reset_at = e.response.headers.get("X-RateLimit-Reset", "unknown")
                    raise GitHubRateLimitError(
                        f"GitHub rate limit hit. Resets at: {reset_at}"
                    )
                if attempt == 2:
                    raise GitHubUnavailableError(f"GitHub API error: {e.response.status_code}")
                await _backoff(attempt)
            except (httpx.NetworkError, httpx.TimeoutException) as e:
                if attempt == 2:
                    raise GitHubUnavailableError(f"GitHub API unavailable: {e}")
                await _backoff(attempt)
            except KeyError:
                if attempt == 2:
                    raise GitHubUnavailableError("GitHub returned unexpected response format")
                await _backoff(attempt)


async def get_installation_repositories(installation_id: int) -> list[dict]:
    """Fetch ALL repositories accessible by this installation, handling pagination."""
    token = await get_installation_access_token(installation_id)
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    repos: list[dict] = []
    url: Optional[str] = f"{GITHUB_API}/installation/repositories"

    async with httpx.AsyncClient(timeout=15.0) as client:
        while url:
            resp = await client.get(url, headers=headers)
            if resp.status_code in (401, 403):
                raise GitHubAuthError(
                    f"GitHub authentication failed fetching repos (HTTP {resp.status_code})"
                )
            resp.raise_for_status()
            data = resp.json()
            repos.extend(data.get("repositories", []))
            url = resp.links.get("next", {}).get("url")

    return repos


async def get_repo_contents(
    installation_id: int, owner: str, repo: str, path: str = "", ref: str = "HEAD"
) -> list[dict] | dict:
    """Fetch file/directory listing from a repository."""
    token = await get_installation_access_token(installation_id)
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    params = {"ref": ref} if ref != "HEAD" else {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()


async def get_file_content(
    installation_id: int, owner: str, repo: str, path: str, ref: str = "HEAD"
) -> str:
    """Fetch raw file content from a repository."""
    token = await get_installation_access_token(installation_id)
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    params = {"ref": ref} if ref != "HEAD" else {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        import base64
        content = resp.json().get("content", "")
        encoding = resp.json().get("encoding", "")
        if encoding == "base64":
            return base64.b64decode(content).decode("utf-8", errors="replace")
        return content


async def search_code(
    installation_id: int, owner: str, repo: str, query: str
) -> list[dict]:
    """Search for code usage of a package in a repository."""
    token = await get_installation_access_token(installation_id)
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"{GITHUB_API}/search/code"
    params = {"q": f"{query} repo:{owner}/{repo}", "per_page": 20}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code == 403:
            return []  # Rate limited — return empty, not an error
        resp.raise_for_status()
        return resp.json().get("items", [])


async def get_github_app_installations() -> list[dict]:
    """List all installations for the authenticated GitHub App."""
    token = _create_jwt()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{GITHUB_API}/app/installations", headers=headers)
        resp.raise_for_status()
        return resp.json()


async def _backoff(attempt: int):
    """Exponential backoff: 1s, 2s, 4s."""
    import asyncio
    await asyncio.sleep(2 ** attempt)
