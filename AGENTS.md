# Repository Guidelines

## Project Structure & Module Organization
Segmentra is a Node.js workspace monorepo. Application code lives in `apps/`: `apps/web` is the Vite + React frontend, and `apps/api` is the TypeScript/Express backend. Shared domain logic lives in `packages/`: `shared` for common types/schemas, `compiler` and `executor` for policy-processing logic, and `db` for migrations and seed scripts. Repository docs are in `docs/` (start with `README.md` and `docs/Architecture.md`; `docs/segmentra_fleet_microsegmentation_firewall_manager_full_specification.md` is the original specification). Container images and compose files live in `infra/` and the repo root (`docker-compose.yml`, hardened override `docker-compose.hardened.yml`).

## Build, Test, and Development Commands
- `npm install`: install workspace dependencies from the repo root.
- `npm run dev`: start the API watcher from `apps/api`.
- `npm run dev -w apps/web`: run the frontend locally with Vite.
- `npm run build`: build all workspaces in dependency order (shared, compiler, executor, api, web).
- `npm run lint`: run workspace lint scripts; today this is most useful in `apps/web`.
- `npm run db:migrate`: apply PostgreSQL migrations from `packages/db/migrations` (plain `.sql` files only; add new ones as `NNN_description.sql`).
- `npm run db:seed`: seed baseline roles, system tags and the initial `admin` user from `packages/db/scripts/seed-roles.js` (password from `SEGMENTRA_ADMIN_PASSWORD`; dev fallback `admin123`).
- `npm run test:integration:ssh-docker`: Docker-based end-to-end test of the SSH deployment path (see `tests/README.md`).

## Coding Style & Naming Conventions
Use TypeScript and ES modules throughout. Follow existing style in each package: frontend components and pages use `PascalCase` filenames, utility modules use lowercase or kebab-case names, and route/service files in the API are organized by feature. Keep indentation consistent with the surrounding file; most of the repo uses 2 spaces. Linting is configured in [apps/web/eslint.config.js](apps/web/eslint.config.js); prefer fixing lint issues before opening a PR.

## Testing Guidelines
There is no unit test framework yet. The automated check is the Docker-based SSH integration test, which builds the API image, boots PostgreSQL plus three SSH target containers, deploys real policies and verifies the resulting `iptables` rules and traffic:
- `npm run test:integration:ssh-docker` (add `-- --keep` to leave the stack running); see [tests/README.md](tests/README.md)

Also verify changes with:
- build affected workspaces with `npm run build`
- lint frontend changes with `npm run lint -w apps/web`
- exercise impacted API routes and UI flows locally

When you add unit tests, place them beside the feature as `*.test.ts` or `*.spec.ts` and avoid introducing a second test framework without discussion.

## Commit & Pull Request Guidelines
Recent history favors short, descriptive subjects focused on shipped behavior, for example `Add policy expiry, notification system, security posture audit, and documentation`. Prefer imperative commit messages that group related work. PRs should include a clear summary, affected areas, migration or seed requirements, linked issues, and screenshots for visible `apps/web` changes.

## Security & Configuration Tips
Do not commit secrets or populated local `.env` files. Database and auth-related changes should note any required environment variables, migration impact, and seed expectations in the PR description.
