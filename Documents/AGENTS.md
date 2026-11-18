# AGENTS.md: Instructions for the AI coding agent

You are building **mcp-audit** from scratch: a zero-dependency TypeScript CLI that audits MCP server configurations. Read these files first, in order:

1. `docs/PRD.md` (what and why)
2. `docs/ARCHITECTURE.md` (how, types, layout)
3. `docs/RULES.md` (rule catalog, the heart of the product)
4. `docs/CLI_SPEC.md` (flags, outputs, exit codes)
5. `docs/PHASES.md` (order of work and Definition of Done)
6. `docs/TESTING.md`, `docs/RELEASE.md`

## Working rules
1. **Follow PHASES.md strictly.** Finish a phase (code, tests, docs, CHANGELOG, commit) before starting the next.
2. **Zero runtime dependencies.** Do not add packages to `dependencies`. Dev dependencies only for build/test/lint.
3. **Security first.** Never print or log raw secret values. Evidence is always redacted. Default scan never spawns processes or uses the network. Never commit real credentials, even in fixtures (build secret-like strings at runtime in tests).
4. **Determinism.** Sort all output. No timestamps in JSON/SARIF output (except an optional `--timestamp` flag).
5. **Strict TypeScript**, no `any` without a comment. Small pure functions. One rule per file.
6. **Test as you go.** No rule without good and bad fixtures. Run `npm run lint && npm run typecheck && npm test` before every commit.
7. **Verify external facts.** Client config paths and the MCP protocol evolve. Where docs say "verify", check current official docs (if you have network access) and update `clients.ts` plus ARCHITECTURE.md. If you cannot verify, note it in `docs/ASSUMPTIONS.md`.
8. **Commit often** using Conventional Commits. One logical change per commit.
9. **Ask the human** (stop and report) when: npm/GitHub auth is missing, the package name is taken, a design decision is ambiguous, or you are about to publish.
10. **Never publish to npm or push tags without explicit human confirmation.**

## Definition of Done (project)
- All P0 and P1 requirements in the PRD implemented; all rules in RULES.md with tests
- CI green on 3 OSes; coverage gate met
- README quickstart works on a clean machine via the packed tarball
- Repo on GitHub with CI, release workflow, Action, pre-commit hook
- Package published (after human approval) and verified with `npx mcp-audit@latest`

## Commands you should create
`npm run build | dev | lint | typecheck | test | test:cov`

## Coding conventions
- File names kebab-case; rule files `sec-001-hardcoded-secret.ts`.
- Exports named, no default exports.
- Use `node:` import prefixes.
- Errors: throw typed errors (`ParseError`, `ConfigError`), catch at engine boundaries.
- Keep functions under ~50 lines; extract helpers into `util/`.

## Kickoff prompt (paste to the agent)
```
Read AGENTS.md and every file it lists. Build mcp-audit phase by phase per docs/PHASES.md,
starting at Phase 0. After each phase: run lint, typecheck, tests; update CHANGELOG.md;
make a Conventional Commit. Do not publish to npm or push tags until I confirm.
Report progress at the end of each phase with a short summary and any open questions.
```
