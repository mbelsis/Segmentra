/**
 * Readable form of a ruleset for people. nftables and iptables rulesets are already text; firewalld and UFW rulesets are
 * JSON documents holding XML or iptables text inside escaped strings, which would otherwise show as one very long line.
 */
function formatPolicyXml(xml: string): string {
  return xml
    .trim()
    .replace(/^<\?xml[^>]*\?>\s*/, '')
    .replace(/\s*(<short>|<ingress-zone|<egress-zone|<rule\b)/g, '\n  $1')
    .replace(/\s*<\/policy>/g, '\n</policy>');
}

function section(path: string, value: unknown, out: string[]): void {
  if (value === null || value === undefined) return;
  if (typeof value === 'string') {
    if (value.includes('\n') || value.trimStart().startsWith('<')) {
      const body = value.includes('<policy') ? formatPolicyXml(value) : value.trim();
      out.push(`# ${path}\n${body}`);
    } else if (value !== '') {
      out.push(`${path}: ${value}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length) out.push(`# ${path}\n${value.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join('\n')}`);
    return;
  }
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) section(path ? `${path}.${key}` : key, child, out);
    return;
  }
  out.push(`${path}: ${String(value)}`);
}

export function formatRuleset(text: string | null | undefined): string {
  const raw = (text ?? '').trim();
  if (!raw) return '(empty)';
  if (!raw.startsWith('{')) return raw;
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    return raw; // Not a JSON document: show it as it is.
  }
  const out: string[] = [];
  section('', doc, out);
  if (!out.length) return raw;
  // Short facts first and together, then one block per policy or rule file. `format` is only for Segmentra itself.
  const facts = out.filter((line) => !line.startsWith('#') && !line.startsWith('format:'));
  const blocks = out.filter((line) => line.startsWith('#'));
  return [facts.join('\n'), ...blocks].filter(Boolean).join('\n\n');
}

/** What it means, per firewall, that Segmentra's rules are not in the running firewall. */
export function rulesMissingMessage(backend: string | null | undefined): string {
  switch (backend) {
    case 'firewalld':
      return "Segmentra's policies are not active in firewalld on this host. firewalld may be stopped, or the policies were removed.";
    case 'ufw':
      return "Segmentra's rules are not active in UFW on this host. UFW may be disabled, or the rules were removed.";
    case 'nftables':
      return "Segmentra's nftables table is not present on this host.";
    case 'iptables':
      return "Segmentra's iptables chains or their jumps are not present on this host.";
    default:
      return "Segmentra's rules are not present on this host.";
  }
}
