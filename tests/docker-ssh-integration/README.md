# Docker SSH Integration Test

This stack exists to validate the real Segmentra deployment path against disposable SSH targets.

It brings up:
- PostgreSQL for the app
- the API container
- three Alpine-based SSH targets with `iptables`, `ping`, `sudo`, password auth, and key auth enabled for the same test user

The starter script is:

```bash
npm run test:integration:ssh-docker
```

What it verifies:
- Docker is available
- `alpine:3.20` can be pulled and used as the base image
- the API can create hosts, policies, approvals, and deployments
- the SSH-direct executor can deploy via password auth
- the SSH-direct executor can deploy via key auth
- `iptables` inside each target matches the expected ACL (Segmentra's `SEGMENTRA-IN` / `SEGMENTRA-OUT` chains, with pre-existing Docker and fail2ban chains left untouched)
- drift detection reports `compliant` after deployment and after unrelated Docker chain changes, and `drifted` once a Segmentra jump is removed
- real container-to-container `ping` traffic is allowed or blocked according to the deployed ACL

Notes:
- The script recreates the integration project from scratch on each run unless `--keep` is passed.
- The entry script lives at [run-docker-ssh-integration.mjs](../run-docker-ssh-integration.mjs).
- It uses the isolated stack defined in [docker-compose.yml](docker-compose.yml).
- The password-auth path is intended for this SSH-direct Dockerized integration flow. The script forces the app to use the `ssh` executor.
