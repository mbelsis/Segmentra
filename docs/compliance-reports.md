# Compliance evidence reports

## Overview

A compliance report is a **point-in-time snapshot of the evidence Segmentra holds**, mapped to the controls of four frameworks. It answers the questions an assessor asks about network segmentation and firewall management: are the hosts covered by a policy, who approved the changes (and were they a different person from the author), what was deployed and what failed, who has access, how old are the credentials, what does the audit trail show, and which IoT assets are not protected by a gateway.

It is **evidence, not a verdict.** The mapping shows which of Segmentra's data supports a control and where attention is needed. It is not an audit opinion, an assessment or a certification, and it does not cover controls outside Segmentra (physical, personnel, encryption, outbound filtering and so on). The control references and the one-line summaries are paraphrased: confirm them against the current standard text with your assessor.

| Framework | Controls mapped |
|---|---|
| PCI DSS v4.0 | 1.2.1, 1.2.2, 1.2.7, 1.3.1, 1.3.2, 6.5.1, 8.2.6, 10.2.1 |
| ISO/IEC 27001:2022 (Annex A) | A.8.20, A.8.22, A.8.9, A.8.32, A.5.3, A.8.2, A.8.15, A.8.16 |
| SOC 2 (Trust Services Criteria) | CC6.1, CC6.3, CC6.6, CC7.2, CC8.1 |
| HIPAA Security Rule | 164.312(a)(1), 164.312(b), 164.312(c)(1), 164.308(a)(1)(ii)(D), 164.308(a)(4), 164.312(e)(1) |

## How it works

```
 hosts, policy versions, approvals, deployments,       ┌─────────────────────────────┐
 users, credentials, audit log, IoT, Kubernetes,  ───▶ │ 1 collect evidence for the  │
 Docker Swarm, latest security scan                    │   period (SQL, no SSH)      │
                                                       │ 2 turn it into measurements │
 optional: read every managed host over SSH  ───────▶  │   with a status each        │
 and compare live rules with the last deployment       │ 3 evaluate each control     │
                                                       │ 4 store the snapshot with   │
                                                       │   its SHA-256 and audit it  │
                                                       └──────────────┬──────────────┘
                                                                      ▼
                                      read it as JSON, a printable HTML page, or CSV datasets;
                                      every read recomputes the hash and shows "verified" or "MISMATCH"
```

1. **Collect.** For the chosen period (default: the last 90 days) the report gathers inventory and coverage, change control, deployments, the latest security audit scan, the audit trail, access, credentials, IoT/OT assets, Kubernetes and Docker Swarm. This is read from Segmentra's database and does not touch any host.
2. **Measure.** The evidence becomes named measurements, each with a status: **OK**, **Attention** or **Info** (see the table below).
3. **Evaluate controls.** Each control lists the measurements that support it. A control is **Evidence** when all of them are OK or informational, **Attention** when any needs attention, and **Not covered** when Segmentra cannot provide evidence for it at all (with the reason stated: for example PCI 1.3.2 outbound restriction, ISO A.8.16 traffic monitoring, HIPAA 164.312(e)(1) transmission security).
4. **Store.** The snapshot is saved unchanged with the SHA-256 of its canonical JSON, and the generation is written to the audit log (`COMPLIANCE_REPORT_GENERATE`). Reports have no update or delete route.
5. **Read.** JSON, a stand-alone HTML page and CSV datasets are produced from the stored snapshot. Every read recomputes the hash and reports whether the stored content is intact.

## Using it

**Web UI.** Compliance Report in the sidebar (under Security Audit).
1. Choose the frameworks and the period. **Thresholds and live check** sets what counts as stale, overdue or inactive (below).
2. **Generate report.** The report opens: header with period, hash and integrity status, the disclaimer, summary cards (red when something needs attention), one table per framework (control, requirement summary, status, the evidence behind it), and lists of hosts without a deployed policy and IoT assets without a gateway.
3. **Open printable report** shows a stand-alone page; use the browser's print dialog to **Save as PDF**. **JSON** downloads the stored report. **CSV dataset** downloads one table for spreadsheets: controls, measurements, hosts, changes, deployment failures, inactive users, SSH credentials, IoT assets, and the **full audit events** of the period.
4. **Stored reports** lists every earlier report; **Open** shows it again, with its integrity re-checked.

**API** (`/api/compliance/reports`)

| Request | Role | Purpose |
|---|---|---|
| `POST /` | operator, approver, admin | Generate and store. Body (all optional): `title`, `frameworks` (`pci-dss-4`, `iso-27001-2022`, `soc2`, `hipaa`), `from`, `to` (ISO timestamps), `staleDays`, `reviewDays`, `credentialMaxAgeDays`, `inactiveUserDays`, `liveDrift`. `liveDrift` needs operator or admin. Returns `{ id, sha256, summary }` |
| `GET /` | every role | List the stored reports |
| `GET /:id?format=json` | every role | The report with `integrity: { sha256, verified }` |
| `GET /:id?format=html` | every role | Stand-alone printable page (served with `Content-Security-Policy: default-src 'none'`, no scripts) |
| `GET /:id?format=csv&dataset=controls\|metrics\|hosts\|changes\|deployment_failures\|users_inactive\|credentials\|iot_assets\|audit_events` | every role | One CSV table. Cells that start with `=`, `+`, `-` or `@` are prefixed so spreadsheets do not evaluate them |

The period is limited to three years. `audit_events` is rebuilt from the append-only audit log for the report's period (the report itself stores aggregates and the lists below, not every event), and a report's own generation event is written after its period ends, so it is not in its own list.

## What is measured

| Measurement | Status is "Attention" when |
|---|---|
| Enabled hosts under a deployed policy (%) | any enabled host has no successful deployment (or its policy was removed by the expiry action) |
| Hosts not deployed for more than *staleDays* (default 90) | any |
| Policy sets approved within *reviewDays* (default 180) | any policy set has no approval in that time |
| Versions approved in the period; high-risk versions approved | information only |
| Versions approved by someone who edited or submitted them | any (Segmentra refuses these, so a non-zero value needs explaining) |
| Approvals waiting more than 7 days | any |
| Deployments with failed hosts in the period | any; also shows total deployments and automatic rollbacks |
| Days since the last security audit scan; critical or high findings in it | no scan, older than 30 days, or any critical/high finding |
| Audit events in the period | none |
| Active accounts; administrator accounts | information; more than 5 administrators |
| Accounts without a login for more than *inactiveUserDays* (default 90) | any |
| SSH credentials whose secret is older than *credentialMaxAgeDays* (default 365) | any |
| Enabled IoT/OT assets without a protecting gateway | any |
| Kubernetes clusters with TLS verification disabled; Kubernetes policies drifted at the last check | any |
| Docker Swarm nodes managed | information |
| Live drift check | any host differs from its last deployment or cannot be read (only when run) |

"Under a deployed policy" means Segmentra recorded a successful deployment for the host. It is **not verified against the host** unless the live drift check is enabled, which reads every managed host over SSH (a few at a time, so it is slow on large inventories) and compares its live rules with the last deployment, exactly like the Compliance check on the Inventory page.

## Limitations

- **Segmentra only knows its own data.** Hosts that are not in the inventory are invisible to the report. A control is "supported" by evidence, not proven: an assessor decides.
- **A snapshot, not a history.** Drift, coverage and the security scan are as of the generation time (the audit trail, approvals and deployments cover the period). To show a trend, generate reports regularly and keep them; Segmentra does not schedule them.
- **Lists are capped at 500 rows** per table (the summary counts are exact). Use the CSV datasets and the audit-event export for the rest.
- **The hash is not a signature.** It detects that a stored report was altered, but anyone with database access who can also recompute and replace the hash could replace a report. For evidence that must resist that, export the HTML/JSON and sign or store it elsewhere.
- **Outbound traffic, traffic monitoring and transmission security are not covered** and are shown as "Not covered" with the reason.

## Tested, and not tested yet

**Tested.** `npm run test:integration:compliance` (35 checks against the real API): generation, the integrity check and tamper detection (a stored report edited in the database is reported as not intact in JSON and HTML, and verifies again when restored), validation, roles, immutability, a fixture of an unmanaged host and IoT assets with and without a gateway reflected in the counts, the lists and the control statuses, period scoping, thresholds, HTML escaping of hostile names and the Content-Security-Policy, CSV formula neutralisation, and the audit-event dataset. In Chrome: signing in, the page, generating a report, the rendered report, the printable report and the CSV downloads.

**Not tested yet**
- **The live drift check inside a report** (the code path reuses the Compliance check; only its role restriction was tested). Run it on a small inventory first.
- **Large inventories** (thousands of hosts or many thousands of audit events) for generation time and the 500-row caps.
- **Saving the printable report as PDF** in different browsers, and printing layout.
- **Typing into the generate form in a browser session**: real keystrokes did not reach the title field in the automated browser used for testing (the page accepted the same input programmatically); try it by hand.
- The correctness of the **control mapping text** against the current official standards: it is paraphrased and unreviewed by an assessor.

## Not supported yet

- Scheduled or automatic generation, and delivery by email.
- Server-side PDF and digitally signed reports.
- Other frameworks (NIST CSF, CIS Controls, NIS2, DORA, ...), and custom control mappings.
- Reports scoped to a subset of hosts, for example only the hosts of a cardholder-data environment (by tag or VLAN).
- Continuous evidence of allowed and blocked connections (firewall logs) and outbound restrictions.
