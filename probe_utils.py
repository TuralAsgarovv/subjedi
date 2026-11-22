from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from typing import Any, Optional

import httpx

from domain_utils import clean_host_input

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PROBE_TIMEOUT_SECONDS = 4.0
_PROBE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; crt-recon/1.0)",
    "Accept": "*/*",
}


def is_private_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def classify_http_status(code: int) -> tuple[str, str]:
    if 200 <= code < 300:
        return "live", f"{code} · Aktiv"
    if 300 <= code < 400:
        return "redirect", f"{code} · Yönləndirmə"
    if code in (401, 403):
        return "restricted", f"{code} · Qorunan"
    if 400 <= code < 500:
        return "restricted", f"{code} · Cavab var"
    return "error", f"{code} · Server xətası"


def is_valid_probe_target(raw: str) -> Optional[str]:
    host = clean_host_input(raw)
    if not host or not _HOSTNAME_RE.match(host):
        return None
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
    ):
        return None
    return host


async def _resolve_ips(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos if info[4]]


async def _probe_scheme(
    client: httpx.AsyncClient, host: str, scheme: str
) -> tuple[Optional[int], Optional[int], Optional[str]]:
    url = f"{scheme}://{host}/"
    started = time.perf_counter()
    try:
        resp = await client.head(url)
        if resp.status_code in (405, 501):
            resp = await client.get(url)
        latency_ms = round((time.perf_counter() - started) * 1000)
        return resp.status_code, latency_ms, None
    except httpx.TimeoutException:
        return None, None, "timeout"
    except httpx.RequestError:
        return None, None, "down"


async def probe_subdomain(client: httpx.AsyncClient, raw_subdomain: str) -> dict[str, Any]:
    host = is_valid_probe_target(raw_subdomain)
    if not host:
        return {
            "subdomain": raw_subdomain,
            "state": "dead",
            "http_code": None,
            "scheme": None,
            "label": "Etibarsız ad",
            "latency_ms": None,
        }

    try:
        ips = await _resolve_ips(host)
    except OSError:
        return {
            "subdomain": host,
            "state": "dead",
            "http_code": None,
            "scheme": None,
            "label": "DNS yoxdur",
            "latency_ms": None,
        }

    if not ips or any(is_private_ip(ip) for ip in ips):
        return {
            "subdomain": host,
            "state": "dead",
            "http_code": None,
            "scheme": None,
            "label": "Məhdud IP",
            "latency_ms": None,
        }

    code, latency, err_https = await _probe_scheme(client, host, "https")
    if code is not None:
        state, label = classify_http_status(code)
        return {
            "subdomain": host,
            "state": state,
            "http_code": code,
            "scheme": "https",
            "label": label,
            "latency_ms": latency,
        }

    code_http, latency_http, err_http = await _probe_scheme(client, host, "http")
    if code_http is not None:
        state, label = classify_http_status(code_http)
        return {
            "subdomain": host,
            "state": state,
            "http_code": code_http,
            "scheme": "http",
            "label": label,
            "latency_ms": latency_http,
        }

    if err_https == "timeout" and err_http == "timeout":
        return {
            "subdomain": host,
            "state": "timeout",
            "http_code": None,
            "scheme": None,
            "label": "Vaxt aşımı",
            "latency_ms": None,
        }

    return {
        "subdomain": host,
        "state": "down",
        "http_code": None,
        "scheme": None,
        "label": "Əlçatmaz",
        "latency_ms": None,
    }


async def probe_batch(subdomains: list[str], concurrency: int = 15) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        timeout=_PROBE_TIMEOUT_SECONDS,
        headers=_PROBE_HEADERS,
        follow_redirects=False,
    ) as client:

        async def _bounded(sub: str) -> dict[str, Any]:
            async with semaphore:
                return await probe_subdomain(client, sub)

        return await asyncio.gather(*[_bounded(s) for s in subdomains])
