import { getDomain } from 'tldts';

export interface CrtRecord {
  name_value?: unknown;
  common_name?: unknown;
  not_before?: unknown;
  entry_timestamp?: unknown;
}

export interface CertSpotterRecord {
  dns_names?: unknown;
  not_before?: unknown;
}

export interface SubdomainEntry {
  subdomain: string;
  first_seen: string;
}

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const DATE_RE = /^(\d{4}-\d{2}-\d{2})/;

export function cleanHostInput(raw: string): string {
  let value = (raw || '').trim().toLowerCase();
  if (!value) {
    return '';
  }

  const schemeIdx = value.indexOf('://');
  if (schemeIdx !== -1) {
    value = value.slice(schemeIdx + 3);
  }

  for (const sep of ['/', '?', '#']) {
    const idx = value.indexOf(sep);
    if (idx !== -1) {
      value = value.slice(0, idx);
    }
  }

  const atIdx = value.lastIndexOf('@');
  if (atIdx !== -1) {
    value = value.slice(atIdx + 1);
  }

  if (value.startsWith('[') && value.includes(']')) {
    value = value.slice(1, value.indexOf(']'));
  } else if (value.includes(':')) {
    const lastColon = value.lastIndexOf(':');
    const hostPart = value.slice(0, lastColon);
    const portPart = value.slice(lastColon + 1);
    if (portPart === '' || /^\d+$/.test(portPart)) {
      value = hostPart;
    }
  }

  while (value.startsWith('*.')) {
    value = value.slice(2);
  }
  value = value.replace(/^\*+/, '').replace(/^\.+|\.+$/g, '');

  return value;
}

export function normalizeApex(raw: string): string {
  const cleaned = cleanHostInput(raw);
  if (!cleaned) {
    throw new Error('Domen adı boş ola bilməz.');
  }

  if (IPV4_RE.test(cleaned) || !HOSTNAME_RE.test(cleaned)) {
    throw new Error('Etibarlı domen adı daxil edin (məs: example.com).');
  }

  const apex = getDomain(cleaned, { allowPrivateDomains: false });
  if (!apex || !HOSTNAME_RE.test(apex)) {
    throw new Error('Əsas domen (eTLD+1) müəyyən edilə bilmədi.');
  }

  return apex.toLowerCase();
}

export function extractDateYmd(rawDate: unknown): string {
  if (typeof rawDate !== 'string') {
    return '';
  }
  const match = DATE_RE.exec(rawDate.trim());
  return match ? match[1] : '';
}

export function extractCrtSubdomains(
  records: CrtRecord[],
  apex: string
): SubdomainEntry[] {
  const earliestBySub = new Map<string, string>();
  const apexSuffix = `.${apex}`;

  for (const entry of records) {
    if (!entry || typeof entry !== 'object') {
      continue;
    }

    const dateCandidate =
      extractDateYmd(entry.not_before) || extractDateYmd(entry.entry_timestamp);

    const rawNames: string[] = [];
    if (typeof entry.name_value === 'string') {
      rawNames.push(...entry.name_value.split(/\r?\n/));
    }
    if (typeof entry.common_name === 'string') {
      rawNames.push(entry.common_name);
    }

    for (const rawName of rawNames) {
      const tokens = rawName.split(/\s+/);
      for (const token of tokens) {
        if (!token || token.includes('@')) {
          continue;
        }
        const host = cleanHostInput(token);
        if (!host || !HOSTNAME_RE.test(host)) {
          continue;
        }
        if (host !== apex && !host.endsWith(apexSuffix)) {
          continue;
        }

        const prev = earliestBySub.get(host);
        if (prev === undefined) {
          earliestBySub.set(host, dateCandidate);
        } else if (dateCandidate && (!prev || dateCandidate < prev)) {
          earliestBySub.set(host, dateCandidate);
        }
      }
    }
  }

  return Array.from(earliestBySub.entries())
    .map(([subdomain, firstSeen]) => ({
      subdomain,
      first_seen: firstSeen || '—',
    }))
    .sort((a, b) => a.subdomain.localeCompare(b.subdomain));
}

export function extractCertSpotterSubdomains(
  records: CertSpotterRecord[],
  apex: string
): SubdomainEntry[] {
  const earliestBySub = new Map<string, string>();
  const apexSuffix = `.${apex}`;

  for (const entry of records) {
    if (!entry || typeof entry !== 'object') continue;
    const dateCandidate = extractDateYmd(entry.not_before);
    const dnsNames = Array.isArray(entry.dns_names) ? entry.dns_names : [];

    for (const rawName of dnsNames) {
      if (typeof rawName !== 'string' || rawName.includes('@')) continue;
      const host = cleanHostInput(rawName);
      if (!host || !HOSTNAME_RE.test(host)) continue;
      if (host !== apex && !host.endsWith(apexSuffix)) continue;

      const prev = earliestBySub.get(host);
      if (prev === undefined) {
        earliestBySub.set(host, dateCandidate);
      } else if (dateCandidate && (!prev || dateCandidate < prev)) {
        earliestBySub.set(host, dateCandidate);
      }
    }
  }

  return Array.from(earliestBySub.entries())
    .map(([subdomain, firstSeen]) => ({
      subdomain,
      first_seen: firstSeen || '—',
    }))
    .sort((a, b) => a.subdomain.localeCompare(b.subdomain));
}

export function extractHackerTargetSubdomains(
  body: string,
  apex: string
): SubdomainEntry[] {
  const seen = new Set<string>();
  const apexSuffix = `.${apex}`;

  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.includes(',')) continue;
    const rawHost = trimmed.split(',', 1)[0];
    if (!rawHost || rawHost.includes(' ')) continue;
    const host = cleanHostInput(rawHost);
    if (!host || !HOSTNAME_RE.test(host)) continue;
    if (host !== apex && !host.endsWith(apexSuffix)) continue;
    seen.add(host);
  }

  return Array.from(seen)
    .sort((a, b) => a.localeCompare(b))
    .map((subdomain) => ({ subdomain, first_seen: '—' }));
}

export function mergeSubdomainSources(
  lists: SubdomainEntry[][]
): SubdomainEntry[] {
  const merged = new Map<string, string>();

  for (const list of lists) {
    for (const item of list) {
      const date = item.first_seen && item.first_seen !== '—' ? item.first_seen : '';
      const prev = merged.get(item.subdomain);
      if (prev === undefined) {
        merged.set(item.subdomain, date);
      } else if (date && (!prev || date < prev)) {
        merged.set(item.subdomain, date);
      }
    }
  }

  return Array.from(merged.entries())
    .map(([subdomain, firstSeen]) => ({
      subdomain,
      first_seen: firstSeen || '—',
    }))
    .sort((a, b) => a.subdomain.localeCompare(b.subdomain));
}
