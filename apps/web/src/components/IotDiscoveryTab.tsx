import { useEffect, useState } from 'react';

import { api, errorMessage } from '../lib/api';

const TYPES = ['plc', 'hmi', 'sensor', 'camera', 'printer', 'hvac', 'medical', 'other'];

type Row = { ip: string; mac: string; iface: string | null; vendor: string | null; vendorNote: string | null; suggestedType: string; status: string; assetName: string | null; hostname: string | null };

/** Passive discovery: read a gateway's neighbour (ARP/NDP) table, review the devices, add the ones that are IoT/OT assets. */
export function IotDiscoveryTab({ canEdit, isAdmin }: { canEdit: boolean; isAdmin: boolean }) {
  const [gateways, setGateways] = useState<any[]>([]);
  const [gatewayId, setGatewayId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<any>(null);
  const [picked, setPicked] = useState<Record<string, { on: boolean; name: string; assetType: string; criticality: string; zone: string }>>({});
  const [imported, setImported] = useState<any>(null);
  const [oui, setOui] = useState<number | null>(null);
  const [ouiMsg, setOuiMsg] = useState('');
  // Opt-in active probe of a subnet behind the gateway
  const [probeOn, setProbeOn] = useState(false);
  const [probeCidr, setProbeCidr] = useState('');
  const [probeOk, setProbeOk] = useState(false);
  const probeReady = !probeOn || (probeCidr.trim() !== '' && probeOk);

  useEffect(() => {
    api.iot.gateways().then((r) => setGateways(r.gateways)).catch((e) => setError(errorMessage(e)));
    api.iot.ouiStatus().then((r) => setOui(r.entries)).catch(() => {});
  }, []);

  const discover = async () => {
    setBusy(true); setError(''); setResult(null); setImported(null);
    try {
      const r = await api.iot.discover(gatewayId, probeOn ? { sweepCidr: probeCidr.trim() } : undefined);
      setResult(r);
      const init: typeof picked = {};
      for (const d of r.devices as Row[]) init[d.mac] = { on: false, name: '', assetType: d.suggestedType, criticality: 'medium', zone: '' };
      setPicked(init);
    } catch (e: any) { setError(errorMessage(e)); }
    setBusy(false);
  };

  const addSelected = async () => {
    const devices = (result.devices as Row[]).filter((d) => picked[d.mac]?.on).map((d) => ({
      ip: d.ip, mac: d.mac, iface: d.iface, name: picked[d.mac].name.trim() || undefined, assetType: picked[d.mac].assetType,
      criticality: picked[d.mac].criticality, zone: picked[d.mac].zone.trim() || undefined,
    }));
    if (devices.length === 0) return;
    setBusy(true); setError('');
    try { setImported(await api.iot.discoverImport({ gatewayId, devices })); await discover().catch(() => {}); } catch (e: any) { setError(errorMessage(e)); }
    setBusy(false);
  };

  const importOui = async (file: File | undefined) => {
    if (!file) return;
    setOuiMsg('Importing...');
    try {
      const r = await api.iot.importOui(await file.text(), false);
      setOui(r.entries); setOuiMsg(`Imported ${r.imported} vendors (${r.entries} in the list).`);
    } catch (e: any) { setOuiMsg(errorMessage(e)); }
  };

  const th = { textAlign: 'left' as const, padding: '6px 8px', background: '#f7f4ef', borderBottom: '1px solid #e0d6c6', fontSize: '12.5px' };
  const td = { padding: '6px 8px', borderBottom: '1px solid #eee7da', verticalAlign: 'middle' as const, fontSize: '13px' };
  const nSel = Object.values(picked).filter((p) => p.on).length;

  return (
    <>
      <p style={{ color: '#78644e', fontSize: '13px', lineHeight: 1.6, marginTop: 0 }}>
        Finds devices behind an IoT gateway. By default it is <strong>passive</strong>: Segmentra reads the gateway's neighbour (ARP/NDP) table over SSH and nothing is sent to the devices,
        so only devices that talked to the gateway recently are listed. To find quiet devices too, turn on the <strong>active probe</strong> below. Vendors come from the IEEE OUI list; the suggested type is a guess from the vendor name.
      </p>
      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <select value={gatewayId} onChange={(e) => setGatewayId(e.target.value)} style={{ minWidth: 260 }}>
            <option value="">Select a gateway...</option>
            {gateways.map((g) => <option key={g.id} value={g.id}>{g.hostname} ({g.protected_asset_count} assets)</option>)}
          </select>
          <button className="btn-primary" disabled={!canEdit || !gatewayId || busy || !probeReady} onClick={discover}>{busy ? (probeOn ? 'Probing...' : 'Reading...') : 'Discover devices'}</button>
          {!canEdit && <span style={{ color: '#97846c', fontSize: '12.5px' }}>Operator or admin role needed.</span>}
        </div>
        <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid #eee7da' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600 }}>
            <input type="checkbox" style={{ width: 'auto' }} checked={probeOn} onChange={(e) => { setProbeOn(e.target.checked); if (!e.target.checked) setProbeOk(false); }} />
            Also probe a subnet behind the gateway (finds devices that have not talked to it yet)
          </label>
          {probeOn && (
            <div style={{ marginTop: 8, display: 'grid', gap: 8, maxWidth: 640 }}>
              <div>
                <label htmlFor="probe-cidr" style={{ display: 'block', fontSize: '12.5px', marginBottom: 4 }}>Subnet to probe (at most a /24)</label>
                <input id="probe-cidr" value={probeCidr} onChange={(e) => setProbeCidr(e.target.value)} placeholder="e.g. 192.168.10.0/24" style={{ width: 240 }} />
              </div>
              <div style={{ background: '#fdf6ec', border: '1px solid #e8d5a8', borderRadius: 6, padding: '8px 12px', fontSize: '12.5px', color: '#5c4633', lineHeight: 1.5 }}>
                <strong>This sends traffic to the devices.</strong> The gateway sends one ICMP echo (ping) to every address of the subnet, 32 at a time, and the ARP requests that go with it.
                Most devices do not care, but old or fragile OT equipment can react badly to unexpected traffic. Only run it where you are allowed to, and preferably outside production hours.
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '12.5px' }}>
                <input type="checkbox" style={{ width: 'auto' }} checked={probeOk} onChange={(e) => setProbeOk(e.target.checked)} />
                I understand, and I am allowed to probe this network
              </label>
            </div>
          )}
        </div>
        <div style={{ marginTop: 10, fontSize: '12.5px', color: '#78644e' }}>
          Vendor list: {oui === null ? '...' : oui === 0 ? <strong style={{ color: '#8b6914' }}>empty (devices will have no vendor)</strong> : `${oui} entries`}
          {isAdmin && (
            <label style={{ marginLeft: 12 }}>
              Import IEEE <code>oui.csv</code> or <code>oui.txt</code>: <input type="file" accept=".csv,.txt,text/csv,text/plain" onChange={(e) => importOui(e.target.files?.[0])} />
            </label>
          )}
          {ouiMsg && <span style={{ marginLeft: 8 }}>{ouiMsg}</span>}
        </div>
      </div>

      {imported && (
        <div role="status" style={{ background: '#eef4e8', border: '1px solid #c9dcb8', borderRadius: 6, padding: '8px 12px', marginBottom: 12, fontSize: '13px' }}>
          Added {imported.created.length} asset(s){imported.skipped.length ? `, skipped ${imported.skipped.length}: ${imported.skipped.map((s: any) => `${s.ip} (${s.reason})`).join('; ')}` : ''}. {imported.note}
        </div>
      )}

      {result && (
        <div className="card">
          <h4 style={{ marginTop: 0 }}>{result.gateway.hostname}: {result.counts.total} device(s) {result.probe ? `found by probing ${result.probe.cidr} (${result.probe.addresses} addresses) and in the neighbour table` : 'in the neighbour table'}</h4>
          <div style={{ color: '#78644e', fontSize: '12.5px', marginBottom: 8 }}>{result.counts.candidates} new, {result.counts.known} already registered as assets, {result.counts.managedHosts} are hosts in the inventory.</div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr><th style={th}></th><th style={th}>IP</th><th style={th}>MAC</th><th style={th}>Vendor</th><th style={th}>Status</th><th style={th}>Name</th><th style={th}>Type</th><th style={th}>Criticality</th><th style={th}>Zone</th></tr></thead>
            <tbody>
              {(result.devices as Row[]).map((d) => {
                const p = picked[d.mac]; const cand = d.status === 'candidate';
                return (
                  <tr key={d.mac} style={{ opacity: cand ? 1 : 0.6 }}>
                    <td style={td}>{cand && <input type="checkbox" style={{ width: 'auto' }} checked={!!p?.on} onChange={(e) => setPicked({ ...picked, [d.mac]: { ...p, on: e.target.checked } })} />}</td>
                    <td style={td}><code>{d.ip}</code></td>
                    <td style={td}><code>{d.mac}</code></td>
                    <td style={td}>{d.vendor ?? <span style={{ color: '#97846c' }} title={d.vendorNote ?? ''}>unknown</span>}</td>
                    <td style={td}>{d.status === 'candidate' ? 'new' : d.status === 'known' ? `asset: ${d.assetName}` : `host: ${d.hostname}`}</td>
                    <td style={td}>{cand && <input value={p?.name ?? ''} placeholder="auto" onChange={(e) => setPicked({ ...picked, [d.mac]: { ...p, name: e.target.value } })} style={{ width: 130 }} />}</td>
                    <td style={td}>{cand && <select value={p?.assetType} onChange={(e) => setPicked({ ...picked, [d.mac]: { ...p, assetType: e.target.value } })}>{TYPES.map((t) => <option key={t} value={t}>{t}</option>)}</select>}</td>
                    <td style={td}>{cand && <select value={p?.criticality} onChange={(e) => setPicked({ ...picked, [d.mac]: { ...p, criticality: e.target.value } })}>{['critical', 'high', 'medium', 'low'].map((t) => <option key={t} value={t}>{t}</option>)}</select>}</td>
                    <td style={td}>{cand && <input value={p?.zone ?? ''} placeholder="optional" onChange={(e) => setPicked({ ...picked, [d.mac]: { ...p, zone: e.target.value } })} style={{ width: 100 }} />}</td>
                  </tr>
                );
              })}
              {result.devices.length === 0 && <tr><td style={td} colSpan={9}>The neighbour table is empty: no device has talked to the gateway recently.</td></tr>}
            </tbody>
          </table>
          <div className="form-actions" style={{ marginTop: 10 }}>
            <button className="btn-primary" disabled={!canEdit || nSel === 0 || busy} onClick={addSelected}>Add {nSel || ''} selected as assets (protected by {result.gateway.hostname})</button>
          </div>
        </div>
      )}
    </>
  );
}
