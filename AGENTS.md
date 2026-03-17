# Repository Guidelines

## Project Structure & Module Organization
Segmentra is a Node.js workspace monorepo. Application code lives in `apps/`: `apps/web` is the Vite + React frontend, and `apps/api` is the TypeScript/Express backend. Shared domain logic lives in `packages/`: `shared` for common types/schemas, `compiler` and `executor` for policy-processing logic, and `db` for migrations and seed scripts. Repository docs are in `docs/`, with broader design references at the repo root.

## Build, Test, and Development Commands
- `npm install`: install workspace dependencies from the repo root.
- `npm run dev`: start the API watcher from `apps/api`.
- `npm run dev -w apps/web`: run the frontend locally with Vite.
- `npm run build`: build all workspaces.
- `npm run lint`: run workspace lint scripts; today this is most useful in `apps/web`.
- `npm run db:migrate`: apply PostgreSQL migrations from `packages/db/migrations`.
- `npm run db:seed`: seed baseline roles from `packages/db/scripts/seed-roles.js`.

## Coding Style & Naming Conventions
Use TypeScript and ES modules throughout. Follow existing style in each package: frontend components and pages use `PascalCase` filenames, utility modules use lowercase or kebab-case names, and route/service files in the API are organized by feature. Keep indentation consistent with the surrounding file; most of the repo uses 2 spaces. Linting is configured in [apps/web/eslint.config.js](/C:/Users/mbelsis/Documents/GitHub/Segmentra/apps/web/eslint.config.js); prefer fixing lint issues before opening a PR.

## Testing Guidelines
There is no established automated test suite in the repository yet. Until one is added, verify changes with targeted manual checks:
- build affected workspaces with `npm run build`
- lint frontend changes with `npm run lint -w apps/web`
- exercise impacted API routes and UI flows locally

When you add tests, place them beside the feature as `*.test.ts` or `*.spec.ts` and avoid introducing a second test framework without discussion.

## Commit & Pull Request Guidelines
Recent history favors short, descriptive subjects focused on shipped behavior, for example `Add policy expiry, notification system, security posture audit, and documentation`. Prefer imperative commit messages that group related work. PRs should include a clear summary, affected areas, migration or seed requirements, linked issues, and screenshots for visible `apps/web` changes.

## Security & Configuration Tips
Do not commit secrets or populated local `.env` files. Database and auth-related changes should note any required environment variables, migration impact, and seed expectations in the PR description.
