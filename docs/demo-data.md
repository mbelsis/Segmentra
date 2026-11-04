# Demo data

To see real firewalls and traffic instead, use the [test labs](lab.md). To explore the UI without real servers, load the sample dataset after the migrations and the seed. In the local development setup (`./run.sh --start --development`) the database runs on `127.0.0.1:15432` and the loader uses that connection when `DATABASE_URL` is not set:

```bash
npm run db:demo                 # local dev; set DATABASE_URL for another database
npm run db:demo -- --remove     # delete the demo data again
```

The dataset contains demo users with a well-known password, so the loader refuses to load it with `NODE_ENV=production`, into a database that is not on localhost (`DATABASE_URL` host other than `localhost` / `127.0.0.1` / `::1` / a Unix socket), or into a database that already has users or hosts not from the demo dataset, unless you pass `--force` (`npm run db:demo -- --force`; `SEGMENTRA_DEMO_FORCE=1` still works). In the Docker (production) install there is no Node.js on the host; load the file straight into the database container instead:

```bash
docker compose exec -T segmentra-db psql -U segmentra -d segmentra < packages/db/demo/demo-data.sql
docker compose exec -T segmentra-db psql -U segmentra -d segmentra < packages/db/demo/demo-remove.sql   # to remove it
```

It adds four VLANs, nine tags, ten Linux hosts (web, app, database, bastion, monitoring, SCADA and an OT gateway), four policy sets with versions in every lifecycle state (deployed, draft, pending approval, approved and scheduled), six OT/IoT devices protected by the gateway with FORWARD rules, deployments in several states and an audit trail. The file is `packages/db/demo/demo-data.sql` (plain SQL, idempotent: re-running changes nothing). Three demo users are created with the password `SegmentraDemo2026!`: `maria.p` (operator), `nikos.k` (approver) and `ana.v` (viewer). The demo hosts have no SSH credentials, so readiness, compliance and live-rule checks against them fail honestly; attach a credential and point a host at a real machine to go further.
