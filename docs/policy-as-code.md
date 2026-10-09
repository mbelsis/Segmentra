# Policy as code

## Overview

A policy set can be exported to, and imported from, a **YAML or JSON document**. The document refers to tags, VLANs, hosts and IoT assets **by name**, not by database id, so it can be reviewed in a pull request, kept in Git and applied to another Segmentra instance. An import is a **plan/apply** operation:

- **It never approves or deploys anything.** It creates the policy set, or adds a new **DRAFT** version to the policy set with the same name. The draft goes through the normal submit, approve and deploy workflow (including separation of duties: the user who imported a version cannot approve it).
- **It is idempotent.** Applying the same document again changes nothing, also before the draft was approved.
- **A dry run shows exactly what would change** (rules added and removed, reordering, warnings) and writes nothing. It runs the same code path as a real import and rolls it back.
- **The scope is protected.** The scope of an existing policy set decides which hosts a deployment targets, so a different scope in the document is only reported, not applied, unless you ask for it.

Three ways to use it: the web UI (Policy Sets → **Import YAML/JSON**, and **Export YAML / JSON** per version), the API, and the command-line tool `scripts/segmentra-policy.mjs` for CI.

## The document

```yaml
apiVersion: segmentra.io/v1
kind: PolicySet
metadata:
  name: web-servers            # identity: the policy set is matched by this name
  description: Access to the web tier
spec:
  scope:                       # which hosts the policy applies to (see below)
    type: TAG
    tag: web
  interfaceScope:              # optional; default ALL_INTERFACES
    type: ALL_INTERFACES
  changeSummary: Open 8443 for the corporate network   # optional; becomes the version's change summary
  rules:
    - order: 10                # optional; default 10, 20, 30, ... by position. Must be unique
      direction: IN            # IN (default), OUT, BOTH or FORWARD
      action: ALLOW            # ALLOW or DENY
      protocol: tcp            # tcp, udp, icmp or any
      ports: "80,443,8000-8100"   # optional; tcp/udp only
      source: 10.0.0.0/8       # a string is a CIDR (or comma list, or any); see "References"
      comment: web from corp
    - order: 20
      action: ALLOW
      protocol: tcp
      ports: "5432"
      source: { type: TAG, name: app-servers }
      log: LOG                 # NONE (default), LOG or LOG_RATE_LIMITED
    - order: 30
      direction: FORWARD       # gateways: needs a destination
      action: ALLOW
      protocol: tcp
      ports: "502"
      source: { type: HOST, name: hmi-01 }
      destination: { type: IOT_ASSET, name: plc-line-3 }
      interfaceScope: { type: INTERFACE_ROLE, roles: [data] }   # optional per-rule override
```

**Scope** (`spec.scope`)

| Type | Fields |
|---|---|
| `TAG` | `tag`: the tag name |
| `VLAN` | `vlan`: the VLAN name, or `vlanTag`: its 802.1Q number |
| `HOST_LIST` | `hosts`: a list of hostnames |

**Interface scope** (`spec.interfaceScope`, and per rule): `ALL_INTERFACES`, `INTERFACE_NAME` with `names: [eth0]`, or `INTERFACE_ROLE` with `roles: [data]`. A rule without `interfaceScope` follows the policy's.

**References** (`source`, `destination`): a string is a CIDR, a comma-separated list of CIDRs or `any`. Otherwise an object: `{ type: CIDR, value: ... }`, or `{ type: TAG | VLAN | HOST, name: ... }` (`IOT_ASSET` is only allowed as a destination). `id: <uuid>` can be used instead of `name` for a reference on the same instance. An export uses names wherever the entity exists.

**Strict validation.** Unknown keys are errors, so a typo such as `port:` instead of `ports:` is reported instead of silently ignored. All problems of a document are reported together, each with its path (`spec.rules[2].source`): schema errors, unknown or ambiguous names, duplicate `order` values, invalid CIDRs and ports, FORWARD rules without destination, and the same rule semantics the UI enforces. Documents are limited to 1 MB and 5000 rules.

## What an import does

| Situation | Result |
|---|---|
| No policy set with that name | `created`: the policy set (scope, description) and a DRAFT v1 |
| The version a new draft would build on (latest deployed or approved, otherwise the latest) already has the same rules and interface scope | `unchanged` |
| An existing DRAFT already has the same content | `unchanged` (matches that draft); re-running before approval never piles up drafts |
| Different rules | `new_version`: a DRAFT vN+1 with the document's rules |
| Different scope | not applied; a warning says so. Applied with `updateScope` (UI checkbox, `--update-scope`, `?updateScope=true`) |
| Several policy sets with the same name | refused (`409 ambiguous_policy_set`); rename them so the name is unique |

The file is the source of truth for the rules: rules not in the document are not in the new version. The sequence of rules (by `order`) is compared, not the numbers, so renumbering alone is not a change; a pure reordering is reported as one. The document does not create tags, VLANs, hosts or IoT assets, and it never deletes a policy set. `metadata.name` is the identity, so renaming it creates a different policy set.

Each import is written to the audit log (`POLICY_IMPORT`), and the importing user is recorded as an editor of the version.

## Command-line tool

`scripts/segmentra-policy.mjs` has no dependencies (Node 20+). Connection: `SEGMENTRA_URL` (default `http://localhost:8080`) and either `SEGMENTRA_TOKEN` or `SEGMENTRA_USER` + `SEGMENTRA_PASSWORD`. Use an account with the `operator` role for `plan` and `apply` (`viewer` is enough for `export`).

```bash
# Export one policy set (a file, or stdout), or all of them into a directory
node scripts/segmentra-policy.mjs export web-servers -o policies/web-servers.yaml
node scripts/segmentra-policy.mjs export --all -d policies/ [--format json] [--version 3]

# What would change? Exit code 2 if something would, with --detailed-exitcode
node scripts/segmentra-policy.mjs plan policies/ --detailed-exitcode

# Create / add DRAFT versions (still need approval in Segmentra)
node scripts/segmentra-policy.mjs apply policies/ [--update-scope]
```

Arguments can be files or directories (`*.yaml`, `*.yml`, `*.json`); a YAML file may contain several documents separated by `---`. Exit codes: `0` ok, `1` error or invalid document, `2` plan with pending changes (`--detailed-exitcode`).

## Git and CI workflow

Segmentra does not pull from Git by itself; the CI system pushes. A typical GitHub Actions setup:

```yaml
name: segmentra-policies
on:
  pull_request: { paths: ["policies/**"] }
  push: { branches: [main], paths: ["policies/**"] }
jobs:
  policies:
    runs-on: ubuntu-latest
    env:
      SEGMENTRA_URL: ${{ vars.SEGMENTRA_URL }}
      SEGMENTRA_TOKEN: ${{ secrets.SEGMENTRA_TOKEN }}   # a short-lived token of a dedicated operator account
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - name: Plan (shows the diff in the PR log, fails on invalid documents)
        if: github.event_name == 'pull_request'
        run: node scripts/segmentra-policy.mjs plan policies/
      - name: Apply (creates DRAFT versions for review and approval in Segmentra)
        if: github.event_name == 'push'
        run: node scripts/segmentra-policy.mjs apply policies/
```

The Segmentra server must be reachable from the runner (self-hosted runners for an on-premises install). Segregation of duties is preserved: the CI account only creates drafts, a different person approves them in Segmentra, and deployment is a separate step.

## API

| Endpoint | Role | Purpose |
|---|---|---|
| `GET /api/policy-sets/:id/export?format=yaml\|json&version=latest\|N\|<version id>` | viewer+ | Download a document. The default version is the one a new draft would build on. Response headers `X-Segmentra-Version` and `X-Segmentra-Version-Status` say which one it is |
| `POST /api/policy-sets/import?dryRun=true\|false&updateScope=true\|false` | operator, admin | Body: YAML text (`Content-Type: application/yaml`), the document as JSON, or `{ "content": "<yaml or json text>" }` |

An import returns `{ dryRun, action, policySetId, name, versionId, versionNumber, versionStatus, matchesVersion, diff: { added, removed, reordered, unchanged }, scopeChanged, scopeUpdated, warnings }` (`201` when something was created, `200` for a dry run or no change), or `400` with `{ error, message, problems: [{ path, message }] }`. The export is deterministic (stable key and rule order, no timestamps), so repeated exports do not create noise in Git.

## Not tested yet

- Downloading an export from the browser (the UI buttons call the same endpoint the tests cover, but the file download itself was not exercised in a browser) and importing a document from a file with the file picker. The import panel was exercised in a browser with pasted text.
- The CLI on Windows and on Node versions other than the one used for development (24).
- The GitHub Actions workflow above is an example and has not been run on a real runner.
- Very large policy sets (thousands of rules) and concurrent imports of the same policy set (the policy set row is locked, which should serialise them, but this was not stress-tested).

## Not supported yet

- Segmentra pulling documents from a Git repository by itself (use CI, as above).
- Managing hosts, tags, VLANs, IoT assets, templates or schedules as code, and deleting or renaming policy sets from a document.
- A published JSON Schema for editor completion (the format is validated by the server).
- Importing several policy sets atomically (the CLI applies documents one by one).
- Approving or deploying from a document: by design the review and approval stay in Segmentra.
