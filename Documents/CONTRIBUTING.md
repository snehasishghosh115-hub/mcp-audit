# Contributing

1. Fork and clone; `npm ci`.
2. Create a branch: `feat/<short-name>` or `fix/<short-name>`.
3. Make changes with tests. Run `npm run lint && npm run typecheck && npm test`.
4. Use Conventional Commits (`feat: add MCPA-SEC-011`).
5. Open a PR describing what and why; link an issue for new rules.

**Adding a rule:** follow the checklist at the bottom of [docs/RULES.md](docs/RULES.md).
**Adding a client:** edit `src/discovery/clients.ts`, add fixtures in `test/fixtures/<client>/`, update the table in `docs/ARCHITECTURE.md`.
**Never** commit real secrets, including in fixtures.
