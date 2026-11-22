import { normalizeApex } from './domain.ts';

export function parseAllowedDomains(value: string | undefined): Set<string> {
  const entries = (value ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  const allowedDomains = new Set<string>();

  for (const entry of entries) {
    let apex: string;
    try {
      apex = normalizeApex(entry);
    } catch (error) {
      throw new Error(`ALLOWED_DOMAINS contains an invalid domain: ${entry}`, {
        cause: error,
      });
    }

    const bareEntry = entry.toLowerCase().replace(/\.$/, '');
    if (bareEntry !== apex) {
      throw new Error(`ALLOWED_DOMAINS must contain apex domains only: ${entry}`);
    }
    allowedDomains.add(apex);
  }

  return allowedDomains;
}

export function isAllowedDomain(
  host: string,
  allowedDomains: ReadonlySet<string>
): boolean {
  try {
    return allowedDomains.has(normalizeApex(host));
  } catch {
    return false;
  }
}
