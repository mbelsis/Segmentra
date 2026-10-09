import express, { Router } from 'express';
import { z } from 'zod';
import { runSshCommand } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { computeIotCoverage } from '../services/iot-coverage.js';
import {
  NEIGHBOR_COMMAND, buildSweepCommand, isLocallyAdministered, normalizeMac, ouiPrefix, parseNeighbors, parseOuiList, parseSweepCidr, suggestAssetType,
} from '../services/iot-discovery.js';
import { PROTOCOLS } from '../services/iot-protocols.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from '../services/ssh-credentials.js';

/**
 * IoT/OT extras (docs/iot.md): protocol catalog, protection coverage, passive discovery of devices from a gateway's neighbour
 * table, and the IEEE OUI vendor list used to name them. Mounted before the asset router so these single-segment paths are
 * not taken for an asset id.
 */
export const iotExtrasRouter = Router();
iotExtrasRouter.use(requireAuth);
const READ = requireRole('viewer', 'operator', 'approver', 'admin');

iotExtrasRouter.get('/protocols', READ, (_req, res) => {
  res.json({ protocols: PROTOCOLS });
});

iotExtrasRouter.get('/coverage', READ, async (_req, res) => {
  res.json(await computeIotCoverage());
});

// ---- OUI vendor list ----------------------------------------------------------------------------------------------

iotExtrasRouter.get('/oui/status', READ, async (_req, res) => {
  const { rows } = await pool.query(`SELECT count(*)::int AS entries FROM oui_vendors`);
  res.json({ entries: rows[0].entries });
});

const ouiBody = express.text({ type: ['text/csv', 'text/plain', 'application/csv'], limit: '20mb' });
// Body: the IEEE registry as CSV (oui.csv) or text (oui.txt). ?replace=true empties the list first.
iotExtrasRouter.post('/oui', requireRole('admin'), ouiBody, async (req, res) => {
  if (typeof req.body !== 'string' || !req.body.trim()) {
    return res.status(400).json({ error: 'invalid_body', message: 'send the IEEE OUI list (oui.csv or oui.txt) as text/csv or text/plain' });
  }
  const entries = parseOuiList(req.body);
  if (entries.length === 0) return res.status(400).json({ error: 'no_entries', message: 'no OUI entries found; expected the IEEE oui.csv (Registry,Assignment,Organization Name,...) or oui.txt' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (req.query.replace === 'true') await client.query(`DELETE FROM oui_vendors`);
    for (let i = 0; i < entries.length; i += 5000) {
      const chunk = entries.slice(i, i + 5000);
      await client.query(
        `INSERT INTO oui_vendors (prefix, vendor) SELECT * FROM unnest($1::text[], $2::text[]) ON CONFLICT (prefix) DO UPDATE SET vendor = EXCLUDED.vendor`,
        [chunk.map((e) => e.prefix), chunk.map((e) => e.vendor.slice(0, 200))]
      );
    }
    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata) VALUES ($1, 'IOT_OUI_IMPORT', 'oui_vendors', uuid_generate_v4(), $2)`,
      [req.auth!.userId ?? null, JSON.stringify({ entries: entries.length, replace: req.query.replace === 'true' })]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  const { rows } = await pool.query(`SELECT count(*)::int AS entries FROM oui_vendors`);
  res.status(201).json({ imported: entries.length, entries: rows[0].entries });
});

async function vendorsFor(macs: string[]): Promise<Map<string, string>> {
  const prefixes = [...new Set(macs.map(ouiPrefix))];
  if (!prefixes.length) return new Map();
  const { rows } = await pool.query(`SELECT prefix, vendor FROM oui_vendors WHERE prefix = ANY($1::text[])`, [prefixes]);
  return new Map(rows.map((r: any) => [r.prefix, r.vendor]));
}

// ---- passive discovery from a gateway -------------------------------------------------------------------------------

async function loadGateway(id: string) {
  const { rows } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port FROM hosts h
      WHERE h.id::text = $1 AND EXISTS (SELECT 1 FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = h.id AND t.name = 'iot-gateway')`,
    [id]
  );
  return rows[0] ?? null;
}

// Read the gateway's neighbour (ARP/NDP) table over SSH and describe what is on it. Read-only, no sudo, nothing is scanned.
iotExtrasRouter.post('/discover', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = z.object({
    gatewayId: z.string().uuid(),
    // Opt-in active probe of a subnet behind the gateway: it sends traffic to the devices, so it needs an explicit acknowledgement
    sweepCidr: z.string().trim().max(32).optional(),
    confirmActiveProbe: z.boolean().optional(),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  let sweep: { cidr: string; ips: string[] } | null = null;
  if (parsed.data.sweepCidr) {
    if (parsed.data.confirmActiveProbe !== true) {
      return res.status(400).json({ error: 'probe_not_confirmed', message: 'An active probe sends one ICMP echo to every address of the subnet. Confirm that this is acceptable on this network (it can disturb fragile OT devices).' });
    }
    const sw = parseSweepCidr(parsed.data.sweepCidr);
    if (!sw.ok) return res.status(400).json({ error: 'invalid_sweep_subnet', message: sw.error });
    sweep = { cidr: sw.cidr, ips: sw.ips };
  }
  const gw = await loadGateway(parsed.data.gatewayId);
  if (!gw) return res.status(404).json({ error: 'gateway_not_found', message: 'The host does not exist or does not carry the iot-gateway tag' });
  if (!gw.mgmt_ip) return res.status(409).json({ error: 'no_management_ip', message: 'The gateway has no management IP' });

  let cred: MaterializedSshCredential | null = null;
  try {
    cred = await getSshCredentialForHost(gw.id);
    const r = await runSshCommand({ hostname: gw.hostname, ip: String(gw.mgmt_ip).split('/')[0], port: Number(gw.ssh_port) || 22, ...sshAuthFields(cred) }, sweep ? buildSweepCommand(sweep.ips) : NEIGHBOR_COMMAND, { timeoutMs: sweep ? 120_000 : 30_000 });
    if (r.exitCode !== 0) {
      return res.status(502).json({ error: 'ssh_failed', message: `Could not read the neighbour table: ${(r.stderr || `exit code ${r.exitCode}`).trim().split('\n').slice(-1)[0].slice(0, 300)}` });
    }
    const neighbors = parseNeighbors(r.stdout);
    const vendors = await vendorsFor(neighbors.map((n) => n.mac));
    const ouiCount = (await pool.query(`SELECT count(*)::int AS n FROM oui_vendors`)).rows[0].n as number;
    const assets = (await pool.query(`SELECT id, name, mac_address, ip_address FROM iot_assets`)).rows as any[];
    const hosts = (await pool.query(`SELECT hostname, host(mgmt_ip) AS ip FROM hosts WHERE mgmt_ip IS NOT NULL`)).rows as any[];
    const devices = neighbors.map((n) => {
      const vendor = vendors.get(ouiPrefix(n.mac)) ?? null;
      const asset = assets.find((a) => (a.mac_address && normalizeMac(a.mac_address) === n.mac) || (a.ip_address && String(a.ip_address).split('/')[0] === n.ip));
      const host = hosts.find((h) => h.ip === n.ip);
      return {
        ip: n.ip, mac: n.mac, iface: n.iface, state: n.state, vendor,
        vendorNote: vendor ? null : isLocallyAdministered(n.mac) ? 'locally administered address (virtual machine, container or privacy address): no vendor' : ouiCount === 0 ? 'no vendor list imported' : 'vendor not in the imported list',
        suggestedType: suggestAssetType(vendor),
        status: asset ? 'known' : host ? 'managed_host' : 'candidate',
        assetName: asset?.name ?? null, hostname: host?.hostname ?? null,
      };
    });
    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata) VALUES ($1, 'IOT_DISCOVER', 'host', $2, $3)`,
      [req.auth!.userId ?? null, gw.id, JSON.stringify({ gateway: gw.hostname, neighbors: neighbors.length, candidates: devices.filter((d) => d.status === 'candidate').length, ...(sweep ? { activeProbe: sweep.cidr, addressesProbed: sweep.ips.length } : {}) })]
    );
    res.json({
      gateway: { id: gw.id, hostname: gw.hostname }, scannedAt: new Date().toISOString(), ouiEntries: ouiCount, devices,
      probe: sweep ? { cidr: sweep.cidr, addresses: sweep.ips.length } : null,
      counts: { total: devices.length, candidates: devices.filter((d) => d.status === 'candidate').length, known: devices.filter((d) => d.status === 'known').length, managedHosts: devices.filter((d) => d.status === 'managed_host').length },
    });
  } catch (e: any) {
    if (e?.message === 'missing_ssh_credential') return res.status(409).json({ error: 'missing_ssh_credential', message: 'No SSH credential is configured for this gateway' });
    throw e;
  } finally {
    cred?.cleanup();
  }
});

const importSchema = z.object({
  gatewayId: z.string().uuid(),
  devices: z.array(z.object({
    ip: z.string().trim().min(1).max(64),
    mac: z.string().trim().min(1).max(32),
    name: z.string().trim().min(1).max(120).optional(),
    assetType: z.enum(['plc', 'hmi', 'sensor', 'camera', 'printer', 'hvac', 'medical', 'other']).optional(),
    criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
    zone: z.string().trim().max(120).optional(),
    iface: z.string().max(40).nullable().optional(),
  })).min(1).max(200),
});

// Create assets from reviewed discovery results and assign the gateway to them. Vendors are looked up again on the server.
iotExtrasRouter.post('/discover/import', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = importSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const gw = await loadGateway(parsed.data.gatewayId);
  if (!gw) return res.status(404).json({ error: 'gateway_not_found' });

  const net = await import('node:net');
  const created: Array<{ id: string; name: string; ip: string; mac: string }> = [];
  const skipped: Array<{ ip: string; mac: string; reason: string }> = [];
  const macs = parsed.data.devices.map((d) => normalizeMac(d.mac)).filter((m): m is string => !!m);
  const vendors = await vendorsFor(macs);
  for (const d of parsed.data.devices) {
    const mac = normalizeMac(d.mac);
    if (!mac) { skipped.push({ ip: d.ip, mac: d.mac, reason: 'invalid MAC address' }); continue; }
    if (!net.isIP(d.ip)) { skipped.push({ ip: d.ip, mac, reason: 'invalid IP address' }); continue; }
    const dup = await pool.query(`SELECT name FROM iot_assets WHERE lower(mac_address) = $1 OR split_part(ip_address, '/', 1) = $2 LIMIT 1`, [mac, d.ip]);
    if (dup.rows[0]) { skipped.push({ ip: d.ip, mac, reason: `already registered as "${dup.rows[0].name}"` }); continue; }
    const vendor = vendors.get(ouiPrefix(mac)) ?? null;
    const name = d.name ?? `${(vendor ?? 'device').split(/[\s,]+/)[0].toLowerCase()}-${mac.replace(/:/g, '').slice(-6)}`;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const a = (await client.query(
        `INSERT INTO iot_assets (name, asset_type, vendor, mac_address, ip_address, zone, criticality, fingerprint, discovered_by, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true) RETURNING id`,
        [name, d.assetType ?? suggestAssetType(vendor), vendor, mac, d.ip, d.zone ?? null, d.criticality,
         JSON.stringify({ source: 'gateway-neighbors', gateway: gw.hostname, interface: d.iface ?? null, firstSeenAt: new Date().toISOString(), mac, vendor }),
         `gateway-neighbors:${gw.hostname}`]
      )).rows[0];
      await client.query(`INSERT INTO iot_asset_gateways (asset_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [a.id, gw.id]);
      await client.query('COMMIT');
      created.push({ id: a.id, name, ip: d.ip, mac });
    } catch (e: any) {
      await client.query('ROLLBACK').catch(() => {});
      skipped.push({ ip: d.ip, mac, reason: `could not create: ${e?.message ?? e}` });
    } finally {
      client.release();
    }
  }
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata) VALUES ($1, 'IOT_DISCOVER_IMPORT', 'host', $2, $3)`,
    [req.auth!.userId ?? null, gw.id, JSON.stringify({ gateway: gw.hostname, created: created.length, skipped: skipped.length })]
  );
  res.status(created.length ? 201 : 200).json({ created, skipped, note: 'The gateway protects the new assets after its next deployment.' });
});
