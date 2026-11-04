# Backup and restore

Segmentra keeps everything in PostgreSQL. There are two ways to back it up, for two different needs.

| | Configuration backup (JSON) | Full database dump |
|---|---|---|
| **What** | Inventory, auto-tagging rules, OT/IoT assets, policy templates, policy sets with every version and rule, management VLAN and executor settings | The whole database: all of the above plus users, deployments, audit log, notification channels, integrations, Kubernetes clusters, discovery profiles and the encrypted secrets |
| **Where** | **Admin → Backup & Restore** in the UI, or `GET /api/backup/export` | `scripts/segmentra-backup.sh dump` (Docker install) or `pg_dump` |
| **Restores into** | Any Segmentra installation, including a fresh one with a new database and new encryption key; items are matched by name | The same Segmentra version (or a newer one), with the **same `.env`** (`SEGMENTRA_KEK_B64`, `JWT_SECRET`) |
| **Secrets** | Not included: SSH, Kubernetes, LDAP and integration credentials are entered again | Included, encrypted; unusable without the original `SEGMENTRA_KEK_B64` |
| **History** | Not included (deployments, audit log) | Included |
| **Use it for** | Disaster recovery onto a clean install, copying a configuration to another instance, keeping the configuration in Git | Routine backups of a production install, moving the install to another server |

Do both on a production install: a nightly database dump, and a configuration export whenever the inventory or policies change. Store `.env` with the dumps, separately from the database backups themselves.

## Configuration backup (Admin → Backup & Restore)

**Export.** An admin clicks **Download backup**. The file `segmentra-backup-<timestamp>.json` contains:

| Exported | Fields |
|---|---|
| **VLANs** | tag number, name, description, subnet |
| **Tags** | name, description, system flag |
| **Hosts** | hostname, management IP, SSH port, environment, OS family, firewall backend, VLAN (by tag number), enabled, Swarm profile (name, role, address, encrypted overlay), Docker-published-ports flag, tags (by name, manually assigned ones), interfaces (name, role, IP, prefix, VLAN, primary, enabled). No SSH credential assignment |
| **Auto-tagging rules** | name, description, target tag, enabled, priority, criteria (a condition on `vlan_id` is rewritten as the equivalent `vlan_tag` condition so it survives new ids) |
| **OT/IoT assets** | name, description, type, vendor, model, firmware, MAC, IP, VLAN, zone, criticality, fingerprint, discovered-by, enabled, gateways (by hostname), tags |
| **Policy templates** | name, description, category, target tag, auto-apply, interface scope, rules |
| **Policy sets** | name, description, scope (tag, VLAN tag number, or host list by hostname), source template, creator, creation time, and **every version**: number, status, change summary, interface scope, high-risk flag, expiry, the approval trail (submitted/approved/rejected by whom and when, submission note, rejection reason; informational, because on import approved versions need re-approval, see below) and **every rule** (order, direction, action, protocol, ports, source and destination by name, log mode, comment, interface scope) |
| **Settings** | management VLAN (by tag number), deployment executor |

Everything refers to other things by **name** (tags by name, VLANs by their tag number, hosts by hostname, IoT assets by name, users by username). No database ids are exported, so the document restores into a database whose ids are different. Dangling references (a rule whose tag was deleted) are exported as the raw id and reported in `warnings`; they cannot be restored. The export is written to the audit log (`BACKUP_EXPORT`).

**Restore.** On the target installation (migrations and seed done, logged in as admin) choose the file under **Restore from backup**, click **Check (dry run)** to see what would be created, then **Restore**. The import:

- runs in one transaction (a dry run rolls it back; any error rolls everything back);
- creates what is missing and **leaves existing items untouched**: VLANs are matched by tag number, policy versions by policy set name and version number, everything else by name. Running the same import twice changes nothing, and a partial restore (for example only the missing policy sets) works the same way;
- does **not** trust the approval trail in the file (a backup is a plain JSON document anyone can edit, so restoring `APPROVED` versions with an arbitrary `approvedBy` would bypass separation of duties). A version that was `APPROVED`, `DEPLOYED` or `PENDING_APPROVAL` in the backup is created as **`PENDING_APPROVAL`**, submitted by the importing admin, without an approver, and the result has one warning per such version (`policy set "X": version N (APPROVED in the backup) imported as PENDING_APPROVAL, needs re-approval`; the dry run shows the same warnings). An approver other than the importing admin (and other than the version's creator) has to approve it again before it can be deployed. `DRAFT` and `REJECTED` versions keep their status (and the rejection reason); `ARCHIVED` versions stay `ARCHIVED` (they can never be approved or deployed again) but without the approver from the file, so they never count as approval evidence (for example in compliance reports). Usernames that do not exist on the target are dropped from the trail; the importing admin is recorded as creator when the original creator is unknown;
- never deploys anything. The backup's `DEPLOYED` status only meant "this was the deployed version when the backup was taken": after approval, check **Inventory → Active Rules** or **Check Compliance** and redeploy where needed;
- skips a rule whose source or destination cannot be resolved (missing tag, VLAN, host or IoT asset) and says so in the warnings; the version is still created;
- fills in the management VLAN and executor settings only when they are empty on the target;
- is written to the audit log (`BACKUP_IMPORT`, with counts).

After a restore into a fresh installation you still have to: create users and roles (or configure LDAP), add SSH credentials and assign them, re-enter Kubernetes and integration credentials, recreate notification channels and discovery profiles, and redeploy the policies you want enforced.

**API**

```bash
# export
curl -sS -H "Authorization: Bearer $TOKEN" -o backup.json http://localhost:8080/api/backup/export
# dry run, then import (the document itself, or {"content": "<json text>"})
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @backup.json "http://localhost:8080/api/backup/import?dryRun=true"
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @backup.json http://localhost:8080/api/backup/import
```

The response lists `counts` per entity (`created`, `skipped`), `warnings`, and on a malformed document `problems` with paths. Both endpoints need the `admin` role.

**Not covered by the configuration backup:**

| Not exported | Why / what to do |
|---|---|
| SSH, Kubernetes, LDAP and integration **credentials** | Encrypted with the installation's `SEGMENTRA_KEK_B64`; enter them again (or use the database dump with the original `.env`) |
| **Users and roles** | Recreate them or configure LDAP; usernames in the approval trail are kept in the file and matched on restore |
| **Deployments**, their artifacts and the **audit log** | History of this installation; the dump keeps it |
| Notification channels and rules, discovery profiles, Kubernetes clusters and workloads, topology views, compliance reports | Configure again, or use the dump |
| Policy sets with a Kubernetes scope | Reported as a warning |

## Full database dump (Docker install)

```bash
./scripts/segmentra-backup.sh dump                 # -> backups/segmentra-<timestamp>.sql.gz
./scripts/segmentra-backup.sh list
docker compose stop segmentra-app
./scripts/segmentra-backup.sh restore backups/segmentra-20261020T120000Z.sql.gz --yes
docker compose up -d segmentra-app                 # runs pending migrations
```

`dump` runs `pg_dump` inside the `segmentra-db` container with `umask 077`: the backup directory is created `0700`, the dump is written to a temporary `*.partial.*` file (mode 600) and only renamed to its final name when `pg_dump` finished, so a failed dump never leaves a truncated file that looks valid. `restore` first validates the file without touching the database (`gunzip -t`, the `-- PostgreSQL database dump` header and the `-- PostgreSQL database dump complete` trailer that a truncated dump lacks), then asks you to type the database name (or takes `--yes` for scripts; without a terminal it refuses unless `--yes` is given), refuses to run while the API container is up, and finally drops and recreates the `public` schema and loads the dump in **one transaction** (`psql --single-transaction -v ON_ERROR_STOP=1`). If any statement fails, PostgreSQL rolls everything back, including the `DROP SCHEMA`, and the previous database is left exactly as it was. The script honours `COMPOSE_FILE` (written to `.env` by `install.sh --production --hardened`), so it works the same with the hardened override. Rebuilding the installation on another server: install Segmentra, copy the original `.env` over the generated one, start only the database (`docker compose up -d segmentra-db`), restore, then start the rest.

For a development install use the same commands against the dev database, or `pg_dump`/`psql` directly with `DATABASE_URL`.

**Schedule it.** For example, a daily cron entry on the Docker host:

```
15 2 * * * cd /opt/segmentra && ./scripts/segmentra-backup.sh dump >> /var/log/segmentra-backup.log 2>&1
```

and prune old files with `find backups -name 'segmentra-*.sql.gz' -mtime +30 -delete`.

## What is not backed up anywhere

- The **firewall state on the managed hosts** themselves. It is reproduced by redeploying the policies; Segmentra's per-host backups under `/var/backups/segmentra/` on each host are for rollback, not for Segmentra's own recovery.
- **Deployment bundles** in `BUNDLES_DIR` (`/bundles` volume in Docker). They are the rendered artifacts of past deployments and can be regenerated by deploying again; include the volume in your backup if you want to keep them as evidence.

## Tested, and not tested yet

**Tested** (against the demo dataset, through the API): export; dry run (everything already present); deleting the content and restoring it, after which a second export was identical to the first; a repeated import that created nothing; an invalid file rejected with paths; the export refused for a viewer; and a dump followed by a restore of the whole database.

That run dates from 2026-10-20, before restored versions began to need re-approval (2026-11-01), and has not been repeated since. An export taken after a restore now differs from the original for versions that were `APPROVED`, `DEPLOYED` or `PENDING_APPROVAL`, because they come back as `PENDING_APPROVAL` without an approver.

**Not tested yet:** the browser's own download and file-picker steps (the same endpoints were exercised with `curl`); restoring a backup taken by an older Segmentra version into a newer one with schema changes to the exported tables (the document format is versioned, `apiVersion: segmentra.io/v1`, and unknown fields are rejected); and very large inventories (the import inserts row by row).
