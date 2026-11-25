# Contributing

Thank you for helping improve VulnRelay. The project is an alpha: prioritize
accurate vulnerability information, predictable delivery, operator privacy
and changes that can be reviewed and tested independently.

## Getting started

1. Read the [architecture](docs/architecture.md), [roadmap](PROJECT_PLAN.md)
   and relevant issue. For a substantial change, discuss the approach in an
   issue before investing in a large implementation.
2. Work on a branch and keep pull requests focused. Explain the problem, the
   behavior change, any compatibility considerations and the checks run.
3. Follow [development and verification](docs/development.md) to set up
   Python 3.12 or 3.13 and, for UI work, Node 22.22.2+ within 22.x, 24.15+
   within 24.x, or 26+. `make install`,
   `make lint`, `make test`, `make frontend` and `make audit` provide local
   entry points. Run the checks relevant to your change; CI runs the full
   matrix, browser and container checks.
4. Add meaningful behavioral tests and update user documentation when
   behavior changes. Automated tests must not need live API credentials,
   real inventories or a running production installation.

Never commit `.env`, bot tokens, databases, private inventory or generated
dependencies. Preserve source provenance, explain uncertain applicability and
keep AI optional. New sources and connectors need failure, retry and
secret-redaction coverage. Database changes need Alembic migrations and an
upgrade path. Do not describe an unfinished feature as production-ready.

Follow the [code of conduct](CODE_OF_CONDUCT.md), [governance](GOVERNANCE.md)
and pull-request template. Report sensitive security issues through the route
in [SECURITY.md](SECURITY.md), not a public issue. By contributing, you agree
to license your contribution under Apache-2.0.
