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

- `data.vlans`, `data.tags`
- `data.hosts` with their tags, interfaces, Swarm profile and Docker-published-ports flag (no SSH credential assignment)
- `data.tagRules` (auto-tagging rules; a condition on `vlan_id` is written as the equivalent `vlan_tag` condition so it survives new ids)
- `data.iotAssets` with their gateways and tags
- `data.policyTemplates` with their rules
- `data.policySets` with every version (status, change summary, approval trail with usernames, interface scope, expiry) and every rule
- `data.settings`: management VLAN (by VLAN tag) and deployment executor

Everything refers to other things by **name** (tags by name, VLANs by their tag number, hosts by hostname, IoT assets by name, users by username). No database ids are exported, so the document restores into a database whose ids are different. Dangling references (a rule whose tag was deleted) are exported as the raw id and reported in `warnings`; they cannot be restored. The export is written to the audit log (`BACKUP_EXPORT`).

**Restore.** On the target installation (migrations and seed done, logged in as admin) choose the file under **Restore from backup**, click **Check (dry run)** to see what would be created, then **Restore**. The import:

- runs in one transaction (a dry run rolls it back; any error rolls everything back);
- creates what is missing and **leaves existing items untouched**: VLANs are matched by tag number, policy versions by policy set name and version number, everything else by name. Running the same import twice changes nothing, and a partial restore (for example only the missing policy sets) works the same way;
- keeps each policy version's **status and approval trail**. Usernames that do not exist on the target are dropped from the trail (the version keeps its status); the importing admin is recorded as creator when the original creator is unknown;
- never deploys anything. `DEPLOYED` means "this was the deployed version when the backup was taken", not that the hosts have it now: check **Inventory → Active Rules** or **Check Compliance** and redeploy where needed;
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

**Not covered by the configuration backup:** users and roles, SSH/Kubernetes/LDAP/integration credentials, notification channels and rules, discovery profiles, Kubernetes clusters and workloads, topology views, deployments and their artifacts, audit events, compliance reports, policy sets with a Kubernetes scope. Use the database dump for those.

## Full database dump (Docker install)

```bash
./scripts/segmentra-backup.sh dump                 # -> backups/segmentra-<timestamp>.sql.gz
./scripts/segmentra-backup.sh list
docker compose stop segmentra-app
./scripts/segmentra-backup.sh restore backups/segmentra-20261020T120000Z.sql.gz --yes
docker compose up -d segmentra-app                 # runs pending migrations
```

`dump` runs `pg_dump` inside the `segmentra-db` container and writes a gzip file with mode 600. `restore` refuses to run while the API container is up, drops and recreates the `public` schema and loads the file. Rebuilding the installation on another server: install Segmentra, copy the original `.env` over the generated one, start only the database (`docker compose up -d segmentra-db`), restore, then start the rest.

For a development install use the same commands against the dev database, or `pg_dump`/`psql` directly with `DATABASE_URL`.

**Schedule it.** For example, a daily cron entry on the Docker host:

```
15 2 * * * cd /opt/segmentra && ./scripts/segmentra-backup.sh dump >> /var/log/segmentra-backup.log 2>&1
```

and prune old files with `find backups -name 'segmentra-*.sql.gz' -mtime +30 -delete`.

## What is not backed up anywhere

- The **firewall state on the managed hosts** themselves. It is reproduced by redeploying the policies; Segmentra's per-host backups under `/var/backups/segmentra/` on each host are for rollback, not for Segmentra's own recovery.
- **Deployment bundles** in `BUNDLES_DIR` (`/bundles` volume in Docker). They are the rendered artifacts of past deployments and can be regenerated by deploying again; include the volume in your backup if you want to keep them as evidence.

## Not tested yet

The configuration export/import was tested with the demo dataset (export, delete, restore, re-export compared equal) and with repeated imports. Not tested: restoring a backup taken by an older Segmentra version into a newer one with schema changes to the exported tables (the document format is versioned, `apiVersion: segmentra.io/v1`, and unknown fields are rejected), and very large inventories (the import inserts row by row).
