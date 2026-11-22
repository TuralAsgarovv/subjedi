from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from db import SubdomainStore
from domain_utils import (
    extract_certspotter_subdomains,
    extract_crt_subdomains,
    extract_hackertarget_subdomains,
    merge_subdomain_sources,
    normalize_apex,
)
from probe_utils import probe_batch

CRT_SH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"
RECON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; subjedi/1.0)",
    "Accept": "application/json,text/plain,*/*",
}
CRT_TIMEOUT_SECONDS = 8.0
FAST_SOURCE_TIMEOUT_SECONDS = 6.0

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="subjedi",
    description="Subdomen kəşfiyyatı və canlı status yoxlama servisi",
    version="1.0.0",
)

store = SubdomainStore()


@app.on_event("startup")
def on_startup() -> None:
    store.init_db()


async def fetch_crt_sh(client: httpx.AsyncClient, apex: str) -> list[tuple[str, str]]:
    response = await client.get(
        CRT_SH_URL,
        params={"q": f"%.{apex}", "output": "json"},
        timeout=CRT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=429 if response.status_code == 429 else 502,
            detail=f"HTTP {response.status_code}",
        )

    text_body = response.text.strip()
    if not text_body:
        return []

    payload = response.json()
    if not isinstance(payload, list):
        raise HTTPException(status_code=502, detail="Gözlənilməz cavab formatı.")

    return extract_crt_subdomains(payload, apex)


async def fetch_certspotter(client: httpx.AsyncClient, apex: str) -> list[tuple[str, str]]:
    response = await client.get(
        CERTSPOTTER_URL,
        params={
            "domain": apex,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        timeout=FAST_SOURCE_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=429 if response.status_code == 429 else 502,
            detail=f"HTTP {response.status_code}",
        )

    payload = response.json()
    if not isinstance(payload, list):
        raise HTTPException(status_code=502, detail="Gözlənilməz cavab formatı.")

    return extract_certspotter_subdomains(payload, apex)


async def fetch_hackertarget(client: httpx.AsyncClient, apex: str) -> list[tuple[str, str]]:
    response = await client.get(
        HACKERTARGET_URL,
        params={"q": apex},
        timeout=FAST_SOURCE_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=429 if response.status_code == 429 else 502,
            detail=f"HTTP {response.status_code}",
        )

    text_body = response.text.strip()
    if not text_body:
        return []

    lower = text_body.lower()
    if lower.startswith("error ") or "api count exceeded" in lower:
        raise HTTPException(status_code=429, detail=text_body)

    return extract_hackertarget_subdomains(text_body, apex)


async def fetch_all_passive_sources(apex: str) -> list[tuple[str, str]]:
    async with httpx.AsyncClient(headers=RECON_HEADERS, follow_redirects=True) as client:
        results = await asyncio.gather(
            fetch_crt_sh(client, apex),
            fetch_certspotter(client, apex),
            fetch_hackertarget(client, apex),
            return_exceptions=True,
        )

    fulfilled: list[list[tuple[str, str]]] = []
    errors: list[Exception] = []
    for res in results:
        if isinstance(res, BaseException):
            errors.append(res if isinstance(res, Exception) else Exception(str(res)))
        else:
            fulfilled.append(res)

    merged = merge_subdomain_sources(fulfilled) if fulfilled else []

    if not fulfilled or (not merged and errors):
        all_timed_out = errors and all(isinstance(err, httpx.TimeoutException) for err in errors)
        if all_timed_out:
            raise HTTPException(
                status_code=504,
                detail="Mənbə sorğuları vaxt aşımına uğradı. Zəhmət olmasa bir az sonra yenidən cəhd edin.",
            )
        raise HTTPException(
            status_code=502,
            detail="Subdomen mənbələrindən cavab alınmadı. Zəhmət olmasa bir az sonra yenidən cəhd edin.",
        )

    return merged


@app.get("/v1/search")
async def search_subdomains(
    apex: str = Query(..., description="Hədəf domen və ya URL (məs: example.com)"),
    format: Literal["text", "json"] = Query("text", description="Cavab formatı: text | json"),
    dates: int = Query(0, ge=0, le=1, description="Tarixləri daxil et: 0 | 1"),
    refresh: int = Query(0, ge=0, le=1, description="Keşi yenilə: 0 | 1"),
):
    started = time.perf_counter()
    store.init_db()

    try:
        normalized_apex = normalize_apex(apex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    cached_entry = store.get_cached(normalized_apex)
    is_cached = False
    is_stale = False
    rows: list[tuple[str, str]] = []
    fetched_at_ts = time.time()

    if refresh != 1 and cached_entry and cached_entry.is_fresh and cached_entry.rows:
        is_cached = True
        rows = cached_entry.rows
        fetched_at_ts = cached_entry.last_fetched_at
    else:
        try:
            rows = await fetch_all_passive_sources(normalized_apex)
            if rows:
                store.save_results(normalized_apex, rows)
            fetched_at_ts = time.time()
        except HTTPException:
            if cached_entry is not None and cached_entry.rows:
                is_cached = True
                is_stale = True
                rows = cached_entry.rows
                fetched_at_ts = cached_entry.last_fetched_at
            else:
                raise

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    include_dates = dates == 1

    headers = {
        "X-Cache": "STALE" if is_stale else ("HIT" if is_cached else "MISS"),
        "X-Response-Time-Ms": str(elapsed_ms),
    }

    if format == "json":
        fetched_iso = datetime.fromtimestamp(fetched_at_ts, tz=timezone.utc).isoformat()
        cached_probes = store.get_cached_probes([sub for sub, _ in rows]) if include_dates else {}
        subdomains_payload = (
            [
                {
                    "subdomain": sub,
                    "first_seen": first_seen,
                    "probe": cached_probes.get(sub),
                }
                for sub, first_seen in rows
            ]
            if include_dates
            else [sub for sub, _ in rows]
        )
        return JSONResponse(
            content={
                "apex": normalized_apex,
                "count": len(rows),
                "cached": is_cached,
                "stale": is_stale,
                "fetched_at": fetched_iso,
                "elapsed_ms": elapsed_ms,
                "subdomains": subdomains_payload,
            },
            headers=headers,
        )

    lines = (
        [f"{sub}\t{first_seen}" for sub, first_seen in rows]
        if include_dates
        else [sub for sub, _ in rows]
    )
    body = "\n".join(lines) + ("\n" if lines else "")
    return PlainTextResponse(content=body, headers=headers)


class ProbeRequest(BaseModel):
    subdomains: list[str]


@app.post("/v1/probe")
async def probe_subdomains(payload: ProbeRequest):
    store.init_db()
    unique_targets: list[str] = []
    seen: set[str] = set()
    for raw in payload.subdomains:
        cleaned = raw.strip().lower()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_targets.append(cleaned)
        if len(unique_targets) >= 50:
            break

    if not unique_targets:
        raise HTTPException(status_code=400, detail="Yoxlanılacaq subdomen siyahısı boşdur.")

    cached_map = store.get_cached_probes(unique_targets)
    missing = [sub for sub in unique_targets if sub not in cached_map]

    if missing:
        fresh_results = await probe_batch(missing, concurrency=15)
        store.save_probes(fresh_results)
        for item in fresh_results:
            cached_map[item["subdomain"]] = item

    results = {sub: cached_map[sub] for sub in unique_targets if sub in cached_map}
    return JSONResponse(
        content={
            "results": results,
            "cached_count": len(unique_targets) - len(missing),
            "probed_count": len(missing),
        }
    )


@app.get("/v1/stats")
def get_stats():
    store.init_db()
    return JSONResponse(content=store.get_stats())


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
