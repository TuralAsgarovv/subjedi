from __future__ import annotations

import re
from typing import Any
import tldextract

# Offline PSL extractor so serverless/Vercel environments never stall on network fetches
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def clean_host_input(raw: str) -> str:
    """Strip protocol, auth, path, query, fragment, port, wildcards, and trailing dots."""
    value = (raw or "").strip().lower()
    if not value:
        return ""

    # Remove scheme (http://, https://, etc.)
    if "://" in value:
        value = value.split("://", 1)[1]

    # Remove path, query, or hash
    for sep in ("/", "?", "#"):
        if sep in value:
            value = value.split(sep, 1)[0]

    # Remove userinfo (user:pass@host)
    if "@" in value:
        value = value.rsplit("@", 1)[1]

    # Remove IPv6 brackets if present or trailing :port
    if value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    elif ":" in value:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit() or port_part == "":
            value = host_part

    # Strip repeated wildcard prefixes (*. or *.) and leading/trailing dots
    while value.startswith("*."):
        value = value[2:]
    value = value.lstrip("*").strip(".")

    return value


def normalize_apex(raw: str) -> str:
    """Clean raw input, validate domain syntax, and return the true apex domain (eTLD+1)."""
    cleaned = clean_host_input(raw)
    if not cleaned:
        raise ValueError("Domen adı boş ola bilməz.")

    if _IPV4_RE.match(cleaned) or not _HOSTNAME_RE.match(cleaned):
        raise ValueError("Etibarlı domen adı daxil edin (məs: example.com).")

    ext = _EXTRACTOR(cleaned)
    if not ext.domain or not ext.suffix:
        raise ValueError("Əsas domen (eTLD+1) müəyyən edilə bilmədi.")

    apex = f"{ext.domain}.{ext.suffix}".lower()
    if not _HOSTNAME_RE.match(apex):
        raise ValueError("Etibarlı əsas domen daxil edin.")

    return apex


def _extract_date_ymd(raw_date: Any) -> str:
    if not isinstance(raw_date, str):
        return ""
    match = _DATE_RE.match(raw_date.strip())
    return match.group(1) if match else ""


def extract_crt_subdomains(records: list[dict[str, Any]], apex: str) -> list[tuple[str, str]]:
    """
    Extract normalized, deduplicated (subdomain, earliest first_seen) pairs
    from crt.sh JSON entries while stripping heavy certificate metadata.
    """
    earliest_by_sub: dict[str, str] = {}
    apex_suffix = f".{apex}"

    for entry in records:
        if not isinstance(entry, dict):
            continue

        date_candidate = _extract_date_ymd(entry.get("not_before")) or _extract_date_ymd(
            entry.get("entry_timestamp")
        )

        raw_names: list[str] = []
        name_value = entry.get("name_value")
        if isinstance(name_value, str):
            raw_names.extend(name_value.splitlines())

        common_name = entry.get("common_name")
        if isinstance(common_name, str):
            raw_names.append(common_name)

        for raw_name in raw_names:
            for token in raw_name.split():
                if "@" in token:
                    continue
                host = clean_host_input(token)
                if not host or not _HOSTNAME_RE.match(host):
                    continue
                if host != apex and not host.endswith(apex_suffix):
                    continue

                prev_date = earliest_by_sub.get(host)
                if prev_date is None:
                    earliest_by_sub[host] = date_candidate
                elif date_candidate and (not prev_date or date_candidate < prev_date):
                    earliest_by_sub[host] = date_candidate

    return sorted(
        ((sub, date or "—") for sub, date in earliest_by_sub.items()),
        key=lambda item: item[0],
    )


def extract_certspotter_subdomains(
    records: list[dict[str, Any]], apex: str
) -> list[tuple[str, str]]:
    earliest_by_sub: dict[str, str] = {}
    apex_suffix = f".{apex}"

    for entry in records:
        if not isinstance(entry, dict):
            continue
        date_candidate = _extract_date_ymd(entry.get("not_before"))
        dns_names = entry.get("dns_names")
        if not isinstance(dns_names, list):
            continue

        for raw_name in dns_names:
            if not isinstance(raw_name, str) or "@" in raw_name:
                continue
            host = clean_host_input(raw_name)
            if not host or not _HOSTNAME_RE.match(host):
                continue
            if host != apex and not host.endswith(apex_suffix):
                continue

            prev_date = earliest_by_sub.get(host)
            if prev_date is None:
                earliest_by_sub[host] = date_candidate
            elif date_candidate and (not prev_date or date_candidate < prev_date):
                earliest_by_sub[host] = date_candidate

    return sorted(
        ((sub, date or "—") for sub, date in earliest_by_sub.items()),
        key=lambda item: item[0],
    )


def extract_hackertarget_subdomains(body: str, apex: str) -> list[tuple[str, str]]:
    seen: set[str] = set()
    apex_suffix = f".{apex}"

    for line in body.splitlines():
        trimmed = line.strip()
        if not trimmed or "," not in trimmed:
            continue
        raw_host = trimmed.split(",", 1)[0]
        if not raw_host or " " in raw_host:
            continue
        host = clean_host_input(raw_host)
        if not host or not _HOSTNAME_RE.match(host):
            continue
        if host != apex and not host.endswith(apex_suffix):
            continue
        seen.add(host)

    return [(sub, "—") for sub in sorted(seen)]


def merge_subdomain_sources(
    lists: list[list[tuple[str, str]]]
) -> list[tuple[str, str]]:
    merged: dict[str, str] = {}
    for entries in lists:
        for sub, first_seen in entries:
            date = first_seen if first_seen and first_seen != "—" else ""
            prev = merged.get(sub)
            if prev is None:
                merged[sub] = date
            elif date and (not prev or date < prev):
                merged[sub] = date

    return sorted(
        ((sub, date or "—") for sub, date in merged.items()),
        key=lambda item: item[0],
    )
