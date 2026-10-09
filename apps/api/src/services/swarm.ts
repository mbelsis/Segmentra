import type { SwarmProfile } from '@segmentra/compiler';

import { pool } from '../db/pool.js';
import { hostIpOnly } from './ip-utils.js';

/**
 * Docker-related compiler input of a host: its Swarm profile (with the addresses of the other nodes
 * of the same swarm) and whether published ports are covered. Spread into compileHostPolicy's input.
 */
export async function getDockerCompileInput(hostId: string): Promise<{ swarm: SwarmProfile | null; dockerPublishedPorts: boolean }> {
  const { rows } = await pool.query(
    `SELECT swarm_cluster, swarm_role, swarm_encrypted_overlay, docker_published_ports FROM hosts WHERE id = $1`,
    [hostId]
  );
  const h = rows[0];
  if (!h) return { swarm: null, dockerPublishedPorts: false };

  let swarm: SwarmProfile | null = null;
  if (h.swarm_cluster) {
    const { rows: peers } = await pool.query(
      `SELECT COALESCE(NULLIF(btrim(swarm_addr), ''), host(mgmt_ip)) AS addr
         FROM hosts
        WHERE swarm_cluster = $1 AND id <> $2 AND enabled = true`,
      [h.swarm_cluster, hostId]
    );
    const peerCidrs = peers.map((p: any) => hostIpOnly(p.addr)).filter((a: string | null): a is string => !!a);
    swarm = {
      role: h.swarm_role === 'manager' ? 'manager' : 'worker',
      peerCidrs: Array.from(new Set(peerCidrs)),
      encryptedOverlay: Boolean(h.swarm_encrypted_overlay),
    };
  }
  return { swarm, dockerPublishedPorts: Boolean(h.docker_published_ports) };
}
