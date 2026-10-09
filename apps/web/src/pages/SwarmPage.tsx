import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';

type SwarmNode = {
  id: string; hostname: string; mgmt_ip: string; enabled: boolean; firewall_backend: string;
  swarm_role: 'manager' | 'worker' | null; swarm_addr: string | null; swarm_encrypted_overlay: boolean;
  docker_published_ports: boolean; updated_at: string; last_deployed_at: string | null;
};

const fmt = (v: string | null) => (v ? new Date(v).toLocaleString() : 'never');

const warnBox = { background: '#fdf6ec', border: '1px solid #e8d5a8', borderRadius: 6, padding: '6px 10px', fontSize: '12.5px', marginBottom: 6 } as const;

/** Warnings for one swarm, computed from the inventory only (Segmentra does not talk to the Docker daemon). */
function analyse(nodes: SwarmNode[]) {
  const warnings: string[] = [];
  const enabled = nodes.filter((n) => n.enabled);
  if (nodes.length < 2) warnings.push('Only one node is registered. Register every node of the swarm, or its peers will not be allowed through the firewall.');
  if (!enabled.some((n) => n.swarm_role === 'manager')) warnings.push('No enabled manager node is registered.');
  if (nodes.some((n) => !n.enabled)) warnings.push('A disabled node is not allowed by the others after their next deployment, which cuts it off from the swarm.');
  if (new Set(nodes.map((n) => !!n.swarm_encrypted_overlay)).size > 1) warnings.push('The encrypted-overlay setting differs between nodes; it should be the same on every node.');
  const newest = Math.max(...nodes.map((n) => new Date(n.updated_at).getTime()));
  const stale = new Set(
    enabled.filter((n) => !n.last_deployed_at || new Date(n.last_deployed_at).getTime() < newest).map((n) => n.id)
  );
  return { warnings, stale };
}

export function SwarmPage() {
  const [swarms, setSwarms] = useState<Array<{ name: string; nodes: SwarmNode[] }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.swarms().then((r) => setSwarms(r.swarms)).catch((e) => setError(e.message || 'Could not load swarms')).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <h2>Docker Swarm</h2>
      <p style={{ color: '#78644e', maxWidth: 900 }}>
        Overview of the Docker Swarm nodes registered in the Inventory. Segmentra manages the <strong>host firewall</strong> of each node over SSH; it does not talk to the Docker daemon
        and does not filter container-to-container or overlay traffic. This page only reads the Inventory.
      </p>

      <div className="card" style={{ marginBottom: 16 }}>
        <h3 style={{ marginTop: 0 }}>How to register a Docker Swarm</h3>
        <ol style={{ lineHeight: 1.7, paddingLeft: 20, margin: 0 }}>
          <li>Add <strong>every node</strong> of the swarm (managers and workers) as a host in <Link to="/inventory">Inventory</Link> (by hand, bulk import or Discovery). Each needs SSH access and the iptables or nftables backend.</li>
          <li>Edit each host and open the <strong>Docker</strong> section. Enter the same <strong>Swarm name</strong> on all nodes, choose the node's <strong>role</strong> (manager or worker) and, if the node's swarm address (<code>--advertise-addr</code>) is not its management IP, enter it. Tick <em>encrypted overlay</em> if you use <code>--opt encrypted</code> networks.</li>
          <li>Tick <strong>Apply inbound policy rules to Docker-published ports</strong> on the nodes whose published container ports (and the routing mesh) your policy should control. Without it those ports bypass the host firewall.</li>
          <li>Create a policy set that targets the nodes (for example with a tag such as <code>swarm</code>), add rules by <em>published port number</em>, and get it approved. The Swarm cluster ports between the registered nodes are allowed automatically; you do not write rules for them.</li>
          <li>Deploy it to <strong>all nodes</strong> from Deployments. Segmentra never deploys by itself.</li>
          <li><strong>When you add, remove, disable or re-address a node, redeploy the other nodes</strong> so that they allow (or stop allowing) it. This page marks nodes that look out of date.</li>
        </ol>
        <p style={{ fontSize: '12.5px', color: '#78644e', marginBottom: 0 }}>
          Not covered: reading services or stacks from Docker, container-to-container and overlay traffic, firewalld/UFW for published ports. See <code>docs/docker-swarm.md</code>.
        </p>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h3 style={{ marginTop: 0 }}>What stays open between the nodes</h3>
        <ul style={{ lineHeight: 1.7, paddingLeft: 20, margin: 0 }}>
          <li><strong>Allowed automatically</strong>, only from the other <em>registered, enabled</em> nodes of the same swarm: 2377/tcp (managers), 7946 tcp+udp, 4789/udp (the VXLAN overlay) and, with encrypted overlay, ESP. They are placed before your rules.</li>
          <li><strong>Everything else between nodes</strong> (SSH, databases, published services) follows your policy like any other source.</li>
          <li><strong>A node that is not registered</strong> gets none of this. Disabling or removing a node cuts it off after the others are redeployed.</li>
          <li><strong>Container-to-container traffic across nodes is not restricted by Segmentra.</strong> It travels inside the VXLAN tunnel on 4789/udp, which Segmentra allows but cannot look into. Use separate overlay networks per application, Docker's network isolation and encrypted overlays for that.</li>
        </ul>
      </div>

      {error && <div className="error">{error}</div>}
      {loading ? <p>Loading...</p> : swarms.length === 0 ? (
        <div className="card"><p style={{ margin: 0 }}>No swarm is registered yet. Follow the steps above: give hosts a <strong>Swarm name</strong> in the Docker section of their Edit form in the <Link to="/inventory">Inventory</Link>.</p></div>
      ) : swarms.map((sw) => {
        const { warnings, stale } = analyse(sw.nodes);
        return (
          <div className="card" key={sw.name} style={{ marginBottom: 16 }}>
            <h3 style={{ marginTop: 0 }}>{sw.name} <span style={{ fontWeight: 400, fontSize: '13px', color: '#78644e' }}>({sw.nodes.length} node{sw.nodes.length === 1 ? '' : 's'})</span></h3>
            {warnings.map((w) => <div key={w} style={warnBox}>⚠ {w}</div>)}
            {stale.size > 0 && (
              <div style={warnBox}>
                ⚠ {stale.size} node(s) were last deployed before a node of this swarm was added or changed. <Link to="/deployments">Redeploy them</Link>. (An estimate: any edit of a node counts, so it can be a false alarm.)
              </div>
            )}
            <table className="data-table">
              <thead><tr><th>Node</th><th>Role</th><th>Management IP</th><th>Swarm address</th><th>Published ports enforced</th><th>Encrypted overlay</th><th>Last deployed</th><th>Status</th></tr></thead>
              <tbody>
                {sw.nodes.map((n) => (
                  <tr key={n.id}>
                    <td><Link to="/inventory">{n.hostname}</Link></td>
                    <td>{n.swarm_role ?? 'worker'}</td>
                    <td>{n.mgmt_ip}</td>
                    <td>{n.swarm_addr ?? <span style={{ color: '#78644e' }}>= management IP</span>}</td>
                    <td>{n.docker_published_ports ? 'yes' : 'no'}</td>
                    <td>{n.swarm_encrypted_overlay ? 'yes' : 'no'}</td>
                    <td>{fmt(n.last_deployed_at)}</td>
                    <td>{!n.enabled ? 'disabled' : stale.has(n.id) ? 'redeploy needed?' : 'up to date'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
    </div>
  );
}
