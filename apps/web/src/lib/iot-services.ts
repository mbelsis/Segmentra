/** Matching of rules against the IoT/OT protocol catalog served by GET /api/iot-assets/protocols (same logic as the API). */
export type CatalogProtocol = {
  id: string; name: string; category: string; security: 'cleartext' | 'encrypted' | 'mixed'; note: string;
  transports: Array<{ protocol: 'tcp' | 'udp'; ports: string }>;
};

export function portRanges(spec: string | null | undefined): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  for (const part of String(spec ?? '').replace(/\s+/g, '').split(',')) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) return [];
    const lo = Number(m[1]);
    const hi = m[2] ? Number(m[2]) : lo;
    if (lo < 1 || hi > 65535 || lo > hi) return [];
    out.push([lo, hi]);
  }
  return out;
}

/** Catalog services whose default port a rule covers ("tcp 502" is Modbus/TCP). Rules without ports name nothing. */
export function servicesForRule(catalog: CatalogProtocol[], protocol: string, ports: string | null | undefined): CatalogProtocol[] {
  const ranges = portRanges(ports);
  if (ranges.length === 0 || !['tcp', 'udp', 'any'].includes(protocol)) return [];
  if (ranges.reduce((n, [lo, hi]) => n + (hi - lo + 1), 0) > 2000) return [];
  const covers = (port: number) => ranges.some(([lo, hi]) => port >= lo && port <= hi);
  return catalog.filter((def) =>
    def.transports.some((t) => {
      if (protocol !== 'any' && protocol !== t.protocol) return false;
      return portRanges(t.ports).some(([lo, hi]) => (lo === hi ? covers(lo) : ranges.some(([a, b]) => a <= lo && b >= hi)));
    })
  );
}
