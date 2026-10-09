/**
 * Catalog of common OT / IoT / building / camera / medical services by their default port, so rules and reports can say
 * "Modbus/TCP" instead of "tcp/502", and policies can refer to a service by name. The ports are the registered or
 * conventional defaults: a device can be configured to use others, and a catalog label is only a hint (the firewall
 * rule is always the port). Nothing here inspects traffic.
 */

export type ProtocolCategory = 'industrial' | 'building' | 'messaging' | 'camera' | 'medical' | 'print' | 'management';
export type ProtocolDef = {
  id: string;
  name: string;
  category: ProtocolCategory;
  transports: Array<{ protocol: 'tcp' | 'udp'; ports: string }>;
  /** cleartext = no encryption and usually no authentication by design; encrypted = TLS/DTLS by design. */
  security: 'cleartext' | 'encrypted' | 'mixed';
  note: string;
};

export const PROTOCOLS: ProtocolDef[] = [
  { id: 'modbus-tcp', name: 'Modbus/TCP', category: 'industrial', transports: [{ protocol: 'tcp', ports: '502' }], security: 'cleartext', note: 'No authentication or encryption in the protocol: anyone who can reach the port can read and write registers.' },
  { id: 'dnp3', name: 'DNP3', category: 'industrial', transports: [{ protocol: 'tcp', ports: '20000' }, { protocol: 'udp', ports: '20000' }], security: 'cleartext', note: 'Utilities and SCADA. Secure Authentication is optional and often not enabled.' },
  { id: 'ethernet-ip', name: 'EtherNet/IP (explicit)', category: 'industrial', transports: [{ protocol: 'tcp', ports: '44818' }, { protocol: 'udp', ports: '44818' }], security: 'cleartext', note: 'Rockwell/Allen-Bradley and CIP devices.' },
  { id: 'ethernet-ip-io', name: 'EtherNet/IP (implicit I/O)', category: 'industrial', transports: [{ protocol: 'udp', ports: '2222' }], security: 'cleartext', note: 'Cyclic I/O data of CIP devices.' },
  { id: 'iso-tsap', name: 'S7comm / IEC 61850 MMS (ISO-TSAP)', category: 'industrial', transports: [{ protocol: 'tcp', ports: '102' }], security: 'cleartext', note: 'Siemens S7 PLCs and IEC 61850 MMS share port 102; the port cannot tell them apart.' },
  { id: 'opc-ua', name: 'OPC UA', category: 'industrial', transports: [{ protocol: 'tcp', ports: '4840' }], security: 'mixed', note: 'Supports signing and encryption, but "None" security modes exist.' },
  { id: 'opc-ua-tls', name: 'OPC UA (HTTPS)', category: 'industrial', transports: [{ protocol: 'tcp', ports: '4843' }], security: 'encrypted', note: 'OPC UA over HTTPS.' },
  { id: 'iec-104', name: 'IEC 60870-5-104', category: 'industrial', transports: [{ protocol: 'tcp', ports: '2404' }], security: 'cleartext', note: 'Telecontrol in power systems.' },
  { id: 'profinet', name: 'PROFINET (RT/CM)', category: 'industrial', transports: [{ protocol: 'udp', ports: '34962-34964' }], security: 'cleartext', note: 'The real-time traffic is layer 2 and is not seen by an IP firewall; these are the UDP parts.' },
  { id: 'omron-fins', name: 'Omron FINS', category: 'industrial', transports: [{ protocol: 'udp', ports: '9600' }], security: 'cleartext', note: 'Omron PLC memory access.' },
  { id: 'hart-ip', name: 'HART-IP', category: 'industrial', transports: [{ protocol: 'tcp', ports: '5094' }, { protocol: 'udp', ports: '5094' }], security: 'cleartext', note: 'Process instrumentation.' },
  { id: 'niagara-fox', name: 'Niagara Fox', category: 'building', transports: [{ protocol: 'tcp', ports: '1911' }], security: 'cleartext', note: 'Tridium Niagara building automation (the TLS variant uses 4911).' },
  { id: 'bacnet-ip', name: 'BACnet/IP', category: 'building', transports: [{ protocol: 'udp', ports: '47808' }], security: 'cleartext', note: 'Building automation; uses broadcasts, which a routed gateway does not forward.' },
  { id: 'knxnet-ip', name: 'KNXnet/IP', category: 'building', transports: [{ protocol: 'udp', ports: '3671' }], security: 'cleartext', note: 'KNX building automation.' },
  { id: 'mqtt', name: 'MQTT', category: 'messaging', transports: [{ protocol: 'tcp', ports: '1883' }], security: 'cleartext', note: 'Unencrypted MQTT.' },
  { id: 'mqtt-tls', name: 'MQTT over TLS', category: 'messaging', transports: [{ protocol: 'tcp', ports: '8883' }], security: 'encrypted', note: 'Encrypted MQTT.' },
  { id: 'amqp', name: 'AMQP', category: 'messaging', transports: [{ protocol: 'tcp', ports: '5672' }], security: 'cleartext', note: 'Unencrypted AMQP.' },
  { id: 'amqps', name: 'AMQP over TLS', category: 'messaging', transports: [{ protocol: 'tcp', ports: '5671' }], security: 'encrypted', note: 'Encrypted AMQP.' },
  { id: 'coap', name: 'CoAP', category: 'messaging', transports: [{ protocol: 'udp', ports: '5683' }], security: 'cleartext', note: 'Constrained devices; also used by LwM2M.' },
  { id: 'coaps', name: 'CoAP over DTLS', category: 'messaging', transports: [{ protocol: 'udp', ports: '5684' }], security: 'encrypted', note: 'Encrypted CoAP.' },
  { id: 'rtsp', name: 'RTSP', category: 'camera', transports: [{ protocol: 'tcp', ports: '554' }, { protocol: 'udp', ports: '554' }], security: 'cleartext', note: 'Video streams of IP cameras.' },
  { id: 'onvif-discovery', name: 'ONVIF / WS-Discovery', category: 'camera', transports: [{ protocol: 'udp', ports: '3702' }], security: 'cleartext', note: 'Camera discovery (multicast).' },
  { id: 'dicom', name: 'DICOM', category: 'medical', transports: [{ protocol: 'tcp', ports: '104' }, { protocol: 'tcp', ports: '11112' }], security: 'mixed', note: 'Medical imaging; TLS is optional.' },
  { id: 'hl7-mllp', name: 'HL7 (MLLP)', category: 'medical', transports: [{ protocol: 'tcp', ports: '2575' }], security: 'cleartext', note: 'Health data messages; port 2575 is the registered default.' },
  { id: 'ipp', name: 'IPP', category: 'print', transports: [{ protocol: 'tcp', ports: '631' }], security: 'mixed', note: 'Internet Printing Protocol.' },
  { id: 'jetdirect', name: 'Raw printing (JetDirect)', category: 'print', transports: [{ protocol: 'tcp', ports: '9100' }], security: 'cleartext', note: 'Unauthenticated raw print port.' },
  { id: 'snmp', name: 'SNMP', category: 'management', transports: [{ protocol: 'udp', ports: '161' }], security: 'mixed', note: 'SNMPv1/v2c are cleartext with community strings; v3 can encrypt.' },
  { id: 'snmp-trap', name: 'SNMP traps', category: 'management', transports: [{ protocol: 'udp', ports: '162' }], security: 'mixed', note: 'Notifications to a manager.' },
  { id: 'ntp', name: 'NTP', category: 'management', transports: [{ protocol: 'udp', ports: '123' }], security: 'cleartext', note: 'Time synchronisation.' },
  { id: 'syslog', name: 'Syslog (UDP)', category: 'management', transports: [{ protocol: 'udp', ports: '514' }], security: 'cleartext', note: 'Log forwarding.' },
];

export function getProtocol(id: string): ProtocolDef | undefined {
  return PROTOCOLS.find((p) => p.id === id);
}

/** Expand "80,443,8000-8100" into inclusive ranges. Returns null when the spec is not valid. */
export function parsePortRanges(spec: string | null | undefined): Array<[number, number]> | null {
  const s = String(spec ?? '').replace(/\s+/g, '');
  if (!s) return [];
  const out: Array<[number, number]> = [];
  for (const part of s.split(',')) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = m[2] ? Number(m[2]) : lo;
    if (lo < 1 || hi > 65535 || lo > hi) return null;
    out.push([lo, hi]);
  }
  return out;
}

/**
 * Catalog services whose default port a rule covers. A service is named when the rule's protocol (tcp, udp or any) and ports
 * include at least one of its default ports, so "tcp 502" is Modbus/TCP and "tcp 1-1024" names every service in that range.
 * Rules without ports (all ports) name nothing.
 */
export function servicesForRule(protocol: string, ports: string | null | undefined): ProtocolDef[] {
  const ranges = parsePortRanges(ports);
  if (!ranges || ranges.length === 0) return [];
  if (protocol !== 'tcp' && protocol !== 'udp' && protocol !== 'any') return [];
  const covers = (port: number) => ranges.some(([lo, hi]) => port >= lo && port <= hi);
  const named = (def: ProtocolDef) =>
    def.transports.some((t) => {
      if (protocol !== 'any' && protocol !== t.protocol) return false;
      const tr = parsePortRanges(t.ports)!;
      return tr.some(([lo, hi]) => (lo === hi ? covers(lo) : ranges.some(([a, b]) => a <= lo && b >= hi)));
    });
  // A very wide range names too many services to be useful.
  if (ranges.reduce((n, [lo, hi]) => n + (hi - lo + 1), 0) > 2000) return [];
  return PROTOCOLS.filter(named);
}

/** The service shorthand of a policy document, expanded to concrete rules (one per transport). */
export function expandService(id: string): Array<{ protocol: 'tcp' | 'udp'; ports: string }> | null {
  const def = getProtocol(id);
  if (!def) return null;
  return def.transports.map((t) => ({ protocol: t.protocol, ports: t.ports }));
}
