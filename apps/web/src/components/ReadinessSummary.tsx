type Level = 'error' | 'warn' | 'info' | 'ok';

type Item = { level: Level; title: string; text: string };

const ICON: Record<Level, string> = { error: '✗', warn: '⚠', info: 'ℹ', ok: '✓' };
const COLOR: Record<Level, string> = { error: '#a63d2f', warn: '#b26a00', info: '#5c6f78', ok: '#3f6b2a' };
const ORDER: Record<Level, number> = { error: 0, warn: 1, info: 2, ok: 3 };

/** Turn the host readiness result (technical messages from the host checks) into short, plain-language findings. */
export function explainReadiness(result: any): { items: Item[]; raw: string[] } {
  const items: Item[] = [];
  const warnings: string[] = Array.isArray(result.warnings) ? result.warnings : [];
  const errors: string[] = Array.isArray(result.errors) ? result.errors : [];
  const p = result.persistence;
  let persistenceExplained = false;

  for (const e of errors) items.push({ level: 'error', title: 'Cannot deploy to this server', text: e });

  for (const w of warnings) {
    if (/^Python is not installed/.test(w)) {
      items.push({ level: 'info', title: 'Ansible needs Python', text: 'Python is not installed on this server. This only matters if you deploy with the Ansible executor; the default SSH Direct executor does not need it.' });
    } else if (/^Rules will not survive a reboot/.test(w)) {
      persistenceExplained = true;
      const text = p?.distro === 'unsupported'
        ? 'Segmentra can only keep its rules across a restart on Debian, Ubuntu and Red Hat family servers. Here the rules take effect immediately but are lost when the server restarts, so deploy again after a reboot, or persist them yourself.'
        : 'Segmentra could not make its rules survive a restart on this server, so they would be lost when it reboots. Deploy again after a reboot, or see the technical details below.';
      items.push({ level: 'warn', title: 'Rules are lost on reboot', text });
    } else if (/nf_tables kernel module not loaded/.test(w)) {
      items.push({ level: 'info', title: 'nf_tables module not loaded yet', text: 'Usually harmless: the module is loaded the first time nftables is used.' });
    } else if (/ip6tables-restore is not available/.test(w)) {
      items.push({ level: 'warn', title: 'No IPv6 rules', text: 'ip6tables-restore is not installed, so IPv6 rules will not be applied on this server.' });
    } else if (/systemd-run nor nohup/.test(w)) {
      items.push({ level: 'warn', title: 'No automatic lockout protection', text: 'Neither systemd-run nor nohup is available, so Segmentra cannot schedule the automatic revert that restores access if a deployment locks it out.' });
    } else {
      items.push({ level: 'warn', title: 'Note', text: w });
    }
  }

  if (p) {
    if (p.available) {
      const via = p.method ? ` (${p.method})` : '';
      items.push({ level: 'ok', title: 'Rules survive a reboot', text: `Segmentra's rules are restored when the server restarts${via}.` });
    } else if (!persistenceExplained) {
      items.push({ level: 'warn', title: 'Rules may be lost on reboot', text: 'The reboot persistence check did not pass; see the technical details below.' });
    }
  }

  items.sort((a, b) => ORDER[a.level] - ORDER[b.level]);

  // Technical text, each distinct sentence once (the checks repeat themselves for iptables and ip6tables).
  const raw = Array.from(new Set([
    ...errors,
    ...warnings,
    ...(p?.warnings ?? []),
    ...(p?.notes ?? []),
  ].flatMap((m: string) => String(m).split(/;\s+/)).map((m) => m.trim()).filter(Boolean)));

  return { items, raw };
}

export function ReadinessSummary({ result }: { result: any }) {
  const { items, raw } = explainReadiness(result);
  const ready = !!result.ready;
  const needsAttention = items.some((i) => i.level === 'warn');

  return (
    <div style={{ padding: 10, background: ready ? (needsAttention ? '#f4f0e2' : '#e8f5e9') : '#ffebee', borderRadius: 6, marginTop: 4, fontSize: '0.85em', lineHeight: 1.45 }}>
      <div style={{ fontWeight: 700, color: ready ? '#2e5d1f' : '#a63d2f' }}>
        {ready ? (needsAttention ? '✓ Ready to deploy, with notes' : '✓ Ready to deploy') : '✗ Not ready'}
      </div>
      {result.backend && result.backend !== 'unknown' && (
        <div style={{ color: '#5c4633' }}>Firewall: <strong>{result.backend}</strong></div>
      )}
      {items.length > 0 && (
        <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
          {items.map((it, i) => (
            <li key={i} style={{ display: 'flex', gap: 6, marginTop: 5 }}>
              <span style={{ color: COLOR[it.level], flex: '0 0 auto' }} aria-hidden="true">{ICON[it.level]}</span>
              <span>
                <strong style={{ color: COLOR[it.level] }}>{it.title}.</strong> <span style={{ color: '#5c4633' }}>{it.text}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
      {raw.length > 0 && (
        <details style={{ marginTop: 6 }}>
          <summary style={{ cursor: 'pointer', color: '#78644e' }}>Technical details</summary>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18, color: '#5c4633' }}>
            {raw.map((m, i) => <li key={i}>{m}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
