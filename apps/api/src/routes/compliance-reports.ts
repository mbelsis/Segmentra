import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import {
  CSV_DATASETS, DEFAULT_PARAMS, FRAMEWORK_IDS, buildReport, contentHash, csvDataset, renderHtml, type FrameworkId,
} from '../services/compliance-report.js';

/**
 * Compliance evidence reports (docs/compliance-reports.md).
 *   POST /compliance/reports                       generate and store a snapshot
 *   GET  /compliance/reports                       list
 *   GET  /compliance/reports/:id?format=json|html|csv&dataset=...
 * Reports are immutable: there is no update or delete. Every read recomputes the SHA-256 of the stored content.
 */
export const complianceReportsRouter = Router();
complianceReportsRouter.use(requireAuth);

const MAX_PERIOD_DAYS = 3 * 366;
const generateSchema = z.object({
  title: z.string().trim().min(1).max(200).optional(),
  frameworks: z.array(z.enum(FRAMEWORK_IDS)).min(1).max(FRAMEWORK_IDS.length).default([...FRAMEWORK_IDS]),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  staleDays: z.number().int().min(1).max(3650).default(DEFAULT_PARAMS.staleDays),
  reviewDays: z.number().int().min(1).max(3650).default(DEFAULT_PARAMS.reviewDays),
  credentialMaxAgeDays: z.number().int().min(1).max(3650).default(DEFAULT_PARAMS.credentialMaxAgeDays),
  inactiveUserDays: z.number().int().min(1).max(3650).default(DEFAULT_PARAMS.inactiveUserDays),
  liveDrift: z.boolean().default(false),
});

complianceReportsRouter.post('/', requireRole('operator', 'approver', 'admin'), async (req, res) => {
  const parsed = generateSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  // Reading hosts over SSH is an operator/admin capability (same as the compliance checks).
  if (b.liveDrift && !req.auth!.roles.some((r) => r === 'operator' || r === 'admin')) {
    return res.status(403).json({ error: 'forbidden', message: 'The live drift check reads the hosts over SSH and needs the operator or admin role' });
  }
  const to = b.to ? new Date(b.to) : new Date();
  const from = b.from ? new Date(b.from) : new Date(to.getTime() - 90 * 86_400_000);
  if (!(from < to)) return res.status(400).json({ error: 'invalid_period', message: '"from" must be before "to"' });
  if ((to.getTime() - from.getTime()) / 86_400_000 > MAX_PERIOD_DAYS) return res.status(400).json({ error: 'invalid_period', message: `the period is limited to ${MAX_PERIOD_DAYS} days` });

  const report = await buildReport({
    frameworks: b.frameworks as FrameworkId[], from, to, staleDays: b.staleDays, reviewDays: b.reviewDays,
    credentialMaxAgeDays: b.credentialMaxAgeDays, inactiveUserDays: b.inactiveUserDays, liveDrift: b.liveDrift,
  }, { username: req.auth!.username });

  const title = b.title ?? `Compliance evidence ${from.toISOString().slice(0, 10)} to ${to.toISOString().slice(0, 10)}`;
  const { rows } = await pool.query(
    `INSERT INTO compliance_reports (title, frameworks, period_from, period_to, parameters, summary, content, content_sha256, generated_by, generated_by_username)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, created_at`,
    [title, b.frameworks, from, to, JSON.stringify(report.content.parameters), JSON.stringify(report.summary), JSON.stringify(report.content), report.sha256, req.auth!.userId ?? null, req.auth!.username]
  );
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata) VALUES ($1, 'COMPLIANCE_REPORT_GENERATE', 'compliance_report', $2, $3)`,
    [req.auth!.userId ?? null, rows[0].id, JSON.stringify({ title, frameworks: b.frameworks, from: from.toISOString(), to: to.toISOString(), liveDrift: b.liveDrift, sha256: report.sha256 })]
  );
  res.status(201).json({ id: rows[0].id, title, createdAt: rows[0].created_at, sha256: report.sha256, summary: report.summary });
});

complianceReportsRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, title, frameworks, period_from, period_to, summary, content_sha256, generated_by_username, created_at
       FROM compliance_reports ORDER BY created_at DESC LIMIT 200`
  );
  res.json({ reports: rows });
});

complianceReportsRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM compliance_reports WHERE id::text = $1`, [req.params.id]);
  const r = rows[0];
  if (!r) return res.status(404).json({ error: 'not_found' });
  const content = typeof r.content === 'string' ? JSON.parse(r.content) : r.content;
  const intact = contentHash(content) === r.content_sha256;
  const format = String(req.query.format ?? 'json');

  if (format === 'html') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    // A stand-alone page: no scripts, no external resources.
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.send(renderHtml(r, content, intact));
  }
  if (format === 'csv') {
    const dataset = String(req.query.dataset ?? 'controls');
    if (!(CSV_DATASETS as readonly string[]).includes(dataset)) return res.status(400).json({ error: 'invalid_dataset', datasets: CSV_DATASETS });
    const csv = await csvDataset(content, dataset, r);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="compliance-${String(r.id).slice(0, 8)}-${dataset}.csv"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.send(csv);
  }
  if (format !== 'json') return res.status(400).json({ error: 'invalid_format', formats: ['json', 'html', 'csv'] });
  res.json({
    id: r.id, title: r.title, frameworks: r.frameworks, createdAt: r.created_at, generatedBy: r.generated_by_username,
    period: { from: r.period_from, to: r.period_to }, summary: r.summary,
    integrity: { sha256: r.content_sha256, verified: intact }, datasets: CSV_DATASETS, content,
  });
});
