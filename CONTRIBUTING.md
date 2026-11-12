# Contributing

Use Python 3.12+, a virtual environment and `make install` (or the equivalent locked installation in docs/development.md). Run `ruff check backend` and `pytest backend/tests`. Frontend contributors use Node 22+, `npm ci`, `npm run build` and `npm test` inside `frontend/`. CI requires no live source or bot credentials. Local Docker smoke checks exercise a real packaged installation.

Work on a branch, keep changes small enough to review, add meaningful behavioral tests, and update the plan/state when working autonomously. Never commit `.env`, bot tokens, databases or generated dependencies. Preserve source provenance, explain uncertainty and keep all AI optional. New source/connector integrations must include failure cases and secret-redaction checks. Database changes need reversible Alembic migrations. Do not call unfinished features production-ready.

By contributing, you agree to license your contribution under Apache-2.0.

For reproducible environments, dependency updates, browser E2E tests, offline secret checks and release artifacts, follow [docs/development.md](docs/development.md). `make install`, `make lint`, `make test`, `make frontend` and `make audit` provide local entry points. Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [GOVERNANCE.md](GOVERNANCE.md) and the pull-request template. CODEOWNERS documents responsibility; enforced branch review is a GitHub administration setting described in [docs/github-settings.md](docs/github-settings.md).
