# Security Policy

## Status of this software

Segmentra changes firewall rules on real hosts, clusters and gateways. It is a **work in progress**, has been tested mainly in lab environments (see [Not Yet Tested](README.md#not-yet-tested)) and has **not had an independent security review**. It is provided "AS IS", without warranty (see [LICENSE](LICENSE), sections 7 and 8). Before using it on production systems:

- test every policy on non-critical hosts first and keep out-of-band (console) access;
- use the lockout protection, canary rollouts and approvals, and review what a deployment will do;
- follow the [hardening guide](docs/security.md) (secrets, `JWT_SECRET`, `SEGMENTRA_KEK_B64`, the Docker socket, network exposure);
- do not expose the API or the web UI to the internet.

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue.

- Use GitHub's **"Report a vulnerability"** (Security tab → Advisories) on this repository, or
- email **mbelsis17@gmail.com** with the subject `Segmentra security`.

Include the affected version or commit, what you found, how to reproduce it and its impact. Do not include real credentials or customer data.

This is a volunteer-run project. I will try to acknowledge a report within **7 days** and to share a plan or a fix within **90 days**, but there is no guaranteed response time or service level. Please allow time for a fix before disclosing publicly; you will be credited in the release notes if you wish.

## Scope

In scope: the Segmentra API, web UI, compiler, executor, the Docker images and the scripts in this repository (authentication and RBAC bypass, injection, secret exposure, unsafe deployment behaviour, and similar).

Out of scope: weaknesses that need an already-compromised admin account or host, vulnerabilities in third-party software (report these upstream), denial of service by an authenticated administrator, and findings in test fixtures, development defaults (`admin/admin123` in development) or lab containers.

## Supported versions

Only the latest commit on `main` is supported. There are no backported fixes.
