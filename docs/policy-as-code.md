# Policy as code

## Overview

A policy set can be exported to, and imported from, a **YAML or JSON document**. The document refers to tags, VLANs, hosts and IoT assets **by name**, not by database id, so it can be reviewed in a pull request, kept in Git and applied to another Segmentra instance. An import is a **plan/apply** operation:

- **It never approves or deploys anything.** It creates the policy set, or adds a new **DRAFT** version to the policy set with the same name. The draft goes through the normal submit, approve and deploy workflow (including separation of duties: the user who imported a version cannot approve it).
- **It is idempotent.** Applying the same document again changes nothing, also before the draft was approved.
- **A dry run shows exactly what would change** (rules added and removed, reordering, warnings) and writes nothing. It runs the same code path as a real import and rolls it back.
- **The scope is protected.** The scope of an existing policy set decides which hosts a deployment targets, so a different scope in the document is only reported, not applied, unless you ask for it.

Three ways to use it: the web UI (Policy Sets → **Import YAML/JSON**, and **Export YAML / JSON** per version), the API, and the command-line tool `scripts/segmentra-policy.mjs` for CI.

**Why use it.** Rules edited in a web form are hard to review, to diff and to reproduce. With a document in Git you get a reviewable history, pull-request review of firewall changes, the same policy on a test and a production instance, and a fast way to copy a policy set. Segmentra stays the place where policies are approved and deployed; the document only replaces typing the rules in.

## How it works

```
 Git repository / file                        Segmentra
 ┌──────────────────┐   plan / apply     ┌─────────────────────────────────────────────┐
 │ web-servers.yaml │ ─────────────────▶ │ 1 parse YAML/JSON, validate every rule      │
 │  names, rules    │  (CLI, UI or API)  │ 2 resolve tag / VLAN / host names to ids    │
 └──────────────────┘                    │ 3 compare with the base version and drafts  │
          ▲                              │ 4 dry run: report the diff and roll back    │
          │ export (deterministic)       │   apply: add a DRAFT version, audit it      │
          └───────────────────────────── └──────────────────────┬──────────────────────┘
                                                                │ still manual, by someone else
                                                                ▼
                                         submit for approval → approve → deploy (unchanged workflow)
```

1. **Identity is the name.** `metadata.name` finds the policy set. No policy set with that name: it is created. Exactly one: it gets a new version when the rules differ. More than one: the import refuses.
2. **References are names.** Tags, VLANs, hosts and IoT assets are looked up by name at import time and stored as ids, exactly as if the rule had been created in the UI. An export turns the ids back into names. The entities must already exist: a document never creates a tag, VLAN or host.
3. **Validation comes first.** Every rule is validated on its own with the same checks the rule editor applies (ports, CIDRs, protocol/port combinations, FORWARD destinations), unknown keys are errors, and all problems are listed together with their path. Nothing is written when anything is wrong.
4. **The comparison decides what happens.** The document is compared with the *base* version (the one a new draft would build on: the latest deployed or approved version, otherwise the latest) and with existing DRAFTs, rule by rule and in order, ignoring the numbers in `order`. The same content means `unchanged`: this is what makes `apply` safe to run on every push to Git.
5. **A dry run is the real thing, rolled back.** It runs the same code in a database transaction and rolls it back, so what it reports is what an apply would do, including warnings.
6. **The result is a DRAFT.** The new version records the importing user as an editor, an audit event (`POLICY_IMPORT`) is written, and from there the normal workflow applies: submit for approval, approval by a different person (separation of duties applies to imported versions too, and the high-risk detection runs on them), and deployment. Nothing is deployed to a host by an import.

## Using it in the web UI

**Import.** Policy Sets → **Import YAML/JSON** (operators and admins; the button is not shown to other roles).
1. Paste a document, or pick a `.yaml`, `.yml` or `.json` file: its content appears in the text box.
2. Press **Check (dry run)**. A green panel says what would happen (`Would create "web-servers" with a DRAFT v1`, `Would add DRAFT version v3`, or `No change: ... already matches v2 (APPROVED)`) and lists every rule that would be added (`+`) or removed (`-`), or `~ rules reordered`. A red panel lists every problem with its path (for example `spec.rules[1].source: tag "x" does not exist`), and **Import as DRAFT** stays disabled until the document is valid.
3. Press **Import as DRAFT**. The panel now says `Created ...` or `Added DRAFT version ...` and the policy set appears in (or updates in) the list.
4. Open the policy set, **Submit for Approval** on the new version, and let a different user approve it under **Approvals**. The importer is refused with "You cannot approve a policy version that you created, edited or submitted".

Tick *Also change the scope* only when the document's scope (tag, VLAN or host list) should replace the existing policy set's scope; otherwise a different scope is only reported as a warning.

**Export.** Open a policy set: every version has **Export YAML** and **JSON** buttons that download that version as a document (`<policy-set-name>.yaml` or `.json`). Through the API or CLI, `version=latest` (the default) exports the version a new draft would build on.

## A worked example

```bash
# 1. Start from what exists
node scripts/segmentra-policy.mjs export web-servers -o policies/web-servers.yaml

# 2. Edit the file in your editor / a Git branch: open 8443 and block telnet
#      ports: "443,8443"          (rule 10)
#      - action: DENY, protocol: tcp, ports: "23", source: 0.0.0.0/0   (new rule)

# 3. See exactly what would happen (nothing is written; exit code 2 means "changes pending")
node scripts/segmentra-policy.mjs plan policies/web-servers.yaml --detailed-exitcode
#    plan : policies/web-servers.yaml (web-servers): new DRAFT version v3 (DRAFT)
#        + ALLOW IN tcp/443,8443 from 10.0.0.0/8 (web from corp)
#        + DENY IN tcp/23 from 0.0.0.0/0 (no telnet)
#        - ALLOW IN tcp/443 from 10.0.0.0/8 (web from corp)

# 4. Create the DRAFT; running it again changes nothing
node scripts/segmentra-policy.mjs apply policies/web-servers.yaml

# 5. In Segmentra: Submit for Approval -> a different user approves -> deploy as usual
```

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

### `service:` shorthand

Instead of `protocol` and `ports`, a rule can name a service from the OT/IoT catalog, for example `service: modbus-tcp`. A service on more than one transport (DNP3 on tcp and udp) becomes one rule per transport with consecutive order numbers, so leave room in `order`. `service` together with `protocol`, an unknown service (the error lists the known ones) or a collision in order numbers is rejected. See [OT/IoT guide](iot.md#8-industrial-protocols-coverage-and-discovery).

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

## Tested, and not tested yet

**Tested.** `npm run test:integration:policy-code` (48 checks against the real API and the CLI) and a manual run in Chrome: loading a YAML and a JSON file with the file picker, **Check (dry run)** and **Import as DRAFT** for a new policy set and for a new version, the per-version **Export YAML** / **JSON** buttons (content of the generated documents checked), **Submit for Approval**, the refusal when the importing user tries to approve (with the message above), approval by a different user, and the absence of the import button for an approver.

**Not tested yet**

- The browser's own download step: the exported file content was verified by intercepting the download, but a file landing in the Downloads folder was not observed.
- The red validation panel was exercised with pasted text, not with an invalid file loaded through the file picker.
- The CLI on Windows and on Node versions other than the one used for development (24).
- The GitHub Actions workflow above is an example and has not been run on a real runner.
- Very large policy sets (thousands of rules) and concurrent imports of the same policy set (the policy set row is locked, which should serialise them, but this was not stress-tested).

## Not supported yet

- Segmentra pulling documents from a Git repository by itself (use CI, as above).
- Managing hosts, tags, VLANs, IoT assets, templates or schedules as code, and deleting or renaming policy sets from a document.
- A published JSON Schema for editor completion (the format is validated by the server).
- Importing several policy sets atomically (the CLI applies documents one by one).
- Approving or deploying from a document: by design the review and approval stay in Segmentra.
