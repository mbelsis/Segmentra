import express, { Router } from 'express';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  ImportError,
  MAX_DOCUMENT_BYTES,
  applyPolicy,
  buildExportDocument,
  normalizeDocument,
  parseDocumentText,
  pickVersion,
  serializeDocument,
} from '../../services/policy-as-code.js';

/**
 * Policy as code (docs/policy-as-code.md):
 *   GET  /policy-sets/:id/export?format=yaml|json&version=latest|<number>|<version id>
 *   POST /policy-sets/import?dryRun=true&updateScope=true     body: YAML or JSON document
 */
export const policyCodeRouter = Router();
policyCodeRouter.use(requireAuth);

policyCodeRouter.get('/:id/export', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const format = req.query.format === 'json' ? 'json' : 'yaml';
  const set = (await pool.query(`SELECT id, name FROM policy_sets WHERE id::text = $1`, [req.params.id])).rows[0];
  if (!set) return res.status(404).json({ error: 'not_found' });
  const version = await pickVersion(set.id, req.query.version ? String(req.query.version) : undefined);
  if (!version) return res.status(404).json({ error: 'version_not_found', message: 'The policy set has no such version' });

  const text = serializeDocument(await buildExportDocument(set.id, version), format);
  const file = `${String(set.name).replace(/[^A-Za-z0-9._-]+/g, '_')}.${format === 'json' ? 'json' : 'yaml'}`;
  res.setHeader('Content-Type', format === 'json' ? 'application/json; charset=utf-8' : 'application/yaml; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
  res.setHeader('X-Segmentra-Version', String(version.version_number));
  res.setHeader('X-Segmentra-Version-Status', String(version.status));
  res.send(text);
});

// The global JSON parser handles application/json; YAML text arrives as text.
const textBody = express.text({ type: ['text/yaml', 'application/yaml', 'application/x-yaml', 'text/plain'], limit: MAX_DOCUMENT_BYTES });

policyCodeRouter.post('/import', requireRole('operator', 'admin'), textBody, async (req, res) => {
  const dryRun = req.query.dryRun === 'true' || req.query.dryRun === '1';
  const updateScope = req.query.updateScope === 'true' || req.query.updateScope === '1';

  // Accept: raw YAML/JSON text, the document as a JSON body, or { content: "<yaml or json text>" }.
  let raw: unknown;
  if (typeof req.body === 'string') {
    const p = parseDocumentText(req.body);
    if (p.problem) return res.status(400).json({ error: 'invalid_document', message: p.problem, problems: [{ path: '(document)', message: p.problem }] });
    raw = p.value;
  } else if (req.body && typeof req.body === 'object' && typeof (req.body as any).content === 'string') {
    const p = parseDocumentText((req.body as any).content);
    if (p.problem) return res.status(400).json({ error: 'invalid_document', message: p.problem, problems: [{ path: '(document)', message: p.problem }] });
    raw = p.value;
  } else {
    raw = req.body;
  }
  if (raw === undefined || raw === null || typeof raw !== 'object') {
    return res.status(400).json({ error: 'invalid_document', message: 'send the policy document as YAML/JSON text or a JSON body', problems: [] });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { policy, problems } = await normalizeDocument(raw, client);
    if (!policy) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'invalid_policy_document', message: `${problems.length} problem(s) in the document`, problems });
    }
    const result = await applyPolicy(client, policy, { userId: req.auth!.userId ?? null, updateScope, source: `policy-as-code (${req.auth!.username})` });
    // A dry run runs exactly the code path of a real import and rolls it back.
    await client.query(dryRun ? 'ROLLBACK' : 'COMMIT');
    res.status(dryRun || result.action === 'unchanged' ? 200 : result.action === 'created' ? 201 : 201).json({ dryRun, ...result });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e instanceof ImportError) return res.status(e.status).json({ error: e.code, message: e.message });
    throw e;
  } finally {
    client.release();
  }
});
