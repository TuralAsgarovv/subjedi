import dns from 'node:dns/promises';
import net from 'node:net';
import { cleanHostInput } from './domain.ts';

export type ProbeState =
  | 'live'
  | 'redirect'
  | 'restricted'
  | 'error'
  | 'dead'
  | 'timeout'
  | 'down';

export interface ProbeResult {
  subdomain: string;
  state: ProbeState;
  http_code: number | null;
  scheme: 'https' | 'http' | null;
  label: string;
  latency_ms: number | null;
}

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PROBE_TIMEOUT_MS = 4000;
const PROBE_USER_AGENT = 'Mozilla/5.0 (compatible; crt-recon/1.0)';

export function isPrivateIp(ip: string): boolean {
  const normalized = ip.trim().toLowerCase();
  if (!normalized) return true;

  if (net.isIPv4(normalized)) {
    const parts = normalized.split('.').map(Number);
    if (parts.length !== 4) return true;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  if (net.isIPv6(normalized)) {
    if (normalized === '::1' || normalized === '::') return true;
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
      return true;
    }
    if (normalized.startsWith('::ffff:')) {
      return isPrivateIp(normalized.slice(7));
    }
    return false;
  }

  return true;
}

export function classifyHttpStatus(code: number): { state: ProbeState; label: string } {
  if (code >= 200 && code < 300) {
    return { state: 'live', label: `${code} · Aktiv` };
  }
  if (code >= 300 && code < 400) {
    return { state: 'redirect', label: `${code} · Yönləndirmə` };
  }
  if (code === 401 || code === 403) {
    return { state: 'restricted', label: `${code} · Qorunan` };
  }
  if (code >= 400 && code < 500) {
    return { state: 'restricted', label: `${code} · Cavab var` };
  }
  return { state: 'error', label: `${code} · Server xətası` };
}

export function isValidProbeTarget(raw: string): string | null {
  const host = cleanHostInput(raw);
  if (!host || !HOSTNAME_RE.test(host)) return null;
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal')
  ) {
    return null;
  }
  return host;
}

async function tryHttpRequest(
  url: string,
  method: 'HEAD' | 'GET'
): Promise<{ status: number; latencyMs: number }> {
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method,
      redirect: 'manual',
      headers: {
        'User-Agent': PROBE_USER_AGENT,
        Accept: '*/*',
      },
      signal: controller.signal,
    });
    const latencyMs = Math.round(performance.now() - started);
    // Cancel unread response body to avoid socket leaks
    try {
      await response.body?.cancel();
    } catch {
      // ignore body cancel error
    }
    return { status: response.status, latencyMs };
  } finally {
    clearTimeout(timer);
  }
}

async function probeScheme(
  host: string,
  scheme: 'https' | 'http'
): Promise<{ status: number; latencyMs: number } | { errorType: 'timeout' | 'down' }> {
  const url = `${scheme}://${host}/`;
  try {
    let res = await tryHttpRequest(url, 'HEAD');
    if (res.status === 405 || res.status === 501) {
      res = await tryHttpRequest(url, 'GET');
    }
    return res;
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      return { errorType: 'timeout' };
    }
    return { errorType: 'down' };
  }
}

export async function probeSubdomain(rawSubdomain: string): Promise<ProbeResult> {
  const host = isValidProbeTarget(rawSubdomain);
  if (!host) {
    return {
      subdomain: rawSubdomain,
      state: 'dead',
      http_code: null,
      scheme: null,
      label: 'Etibarsız ad',
      latency_ms: null,
    };
  }

  let resolvedIps: string[] = [];
  try {
    const records = await dns.lookup(host, { all: true });
    resolvedIps = records.map((r) => r.address);
  } catch {
    return {
      subdomain: host,
      state: 'dead',
      http_code: null,
      scheme: null,
      label: 'DNS yoxdur',
      latency_ms: null,
    };
  }

  if (resolvedIps.length === 0 || resolvedIps.some(isPrivateIp)) {
    return {
      subdomain: host,
      state: 'dead',
      http_code: null,
      scheme: null,
      label: 'Məhdud IP',
      latency_ms: null,
    };
  }

  const httpsRes = await probeScheme(host, 'https');
  if ('status' in httpsRes) {
    const classified = classifyHttpStatus(httpsRes.status);
    return {
      subdomain: host,
      state: classified.state,
      http_code: httpsRes.status,
      scheme: 'https',
      label: classified.label,
      latency_ms: httpsRes.latencyMs,
    };
  }

  const httpRes = await probeScheme(host, 'http');
  if ('status' in httpRes) {
    const classified = classifyHttpStatus(httpRes.status);
    return {
      subdomain: host,
      state: classified.state,
      http_code: httpRes.status,
      scheme: 'http',
      label: classified.label,
      latency_ms: httpRes.latencyMs,
    };
  }

  if (httpsRes.errorType === 'timeout' && httpRes.errorType === 'timeout') {
    return {
      subdomain: host,
      state: 'timeout',
      http_code: null,
      scheme: null,
      label: 'Vaxt aşımı',
      latency_ms: null,
    };
  }

  return {
    subdomain: host,
    state: 'down',
    http_code: null,
    scheme: null,
    label: 'Əlçatmaz',
    latency_ms: null,
  };
}

export async function probeBatch(
  subdomains: string[],
  concurrency: number = 15
): Promise<ProbeResult[]> {
  const results: ProbeResult[] = new Array(subdomains.length);
  let cursor = 0;

  async function worker() {
    while (cursor < subdomains.length) {
      const idx = cursor++;
      results[idx] = await probeSubdomain(subdomains[idx]);
    }
  }

  const workerCount = Math.min(concurrency, Math.max(1, subdomains.length));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}
