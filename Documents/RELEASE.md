# GitHub and npm Release Guide

> The AI agent cannot always authenticate to GitHub/npm. If `gh auth status` or `npm whoami` fails, STOP and ask the human to log in. Never invent or store tokens in the repo.

## A. One-time human setup
1. Create accounts: GitHub, npm (enable **2FA**).
2. Install: Node >=18, git, GitHub CLI (`gh`). Run `gh auth login` and `npm login`.
3. Check the name: `npm view mcp-audit` (404 = available). If taken, use `@<your-npm-username>/mcp-audit` and set `"publishConfig": {"access":"public"}`.
4. Set in `package.json`: `author`, `repository`, `bugs`, `homepage`, `license: "MIT"`.

## B. Create the repo and first commit
```bash
git init -b main
git add .
git commit -m "chore: scaffold project"
gh repo create <your-username>/mcp-audit --public --source=. --remote=origin --push \
  --description "Security audit CLI for MCP server configs and tool definitions"
gh repo edit --add-topic mcp --add-topic security --add-topic cli --add-topic ai-agents --add-topic supply-chain
```
Commit style: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`). Commit at the end of each phase and each meaningful feature; push `main` (or open PRs if collaborating). Enable branch protection requiring CI.

## C. CI workflow `.github/workflows/ci.yml`
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        node: [18, 20, 22]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ matrix.node }}", cache: npm }
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck
      - run: npm run build
      - run: npm test
```
(Pin actions by commit SHA once stable.)

## D. package.json essentials
```json
{
  "name": "mcp-audit",
  "version": "0.1.0",
  "type": "module",
  "bin": { "mcp-audit": "dist/cli.js" },
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js", "require": "./dist/index.cjs" }
  },
  "files": ["dist", "README.md", "LICENSE", "CHANGELOG.md"],
  "engines": { "node": ">=18" },
  "keywords": ["mcp","model-context-protocol","security","audit","cli","ai","claude","cursor","sarif"],
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch",
    "lint": "eslint .",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "test:cov": "vitest run --coverage",
    "prepublishOnly": "npm run lint && npm run typecheck && npm test && npm run build"
  },
  "publishConfig": { "access": "public", "provenance": true }
}
```
`dist/cli.js` must start with `#!/usr/bin/env node` (tsup `banner`) and be executable.

## E. Pre-publish checklist
- [ ] `npm run lint && npm run typecheck && npm test && npm run build` pass
- [ ] `npm pack --dry-run` lists only `dist`, README, LICENSE, CHANGELOG
- [ ] `npm pack` then in a temp dir `npm i ./mcp-audit-0.1.0.tgz && npx mcp-audit --version` works
- [ ] README quickstart verified; CHANGELOG updated; version bumped (`npm version minor`)
- [ ] No secrets in repo (`git log -p | grep -iE "ghp_|sk-|AKIA"` empty)

## F. Publish
**Manual (first release):**
```bash
npm publish --access public
git push --follow-tags
gh release create v0.1.0 --generate-notes
```
**Automated with provenance** `.github/workflows/release.yml`:
```yaml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  id-token: write      # npm provenance
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, registry-url: "https://registry.npmjs.org", cache: npm }
      - run: npm ci
      - run: npm test
      - run: npm publish --provenance --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
      - run: gh release create "$GITHUB_REF_NAME" --generate-notes
        env:
          GH_TOKEN: ${{ github.token }}
```
Create an npm **granular automation token** limited to this package, then add it with `gh secret set NPM_TOKEN`. (npm trusted publishing via OIDC is an alternative that removes the token; follow current npm docs.)

## G. After publishing
1. `npx mcp-audit@latest --version` from a clean directory.
2. Verify the npm page shows provenance, README, and correct links.
3. Add the GitHub Action (Phase 5) and tag `v1` major alias.
4. Run the launch checklist in PHASES.md Phase 8.

## H. Versioning
SemVer. New rules in minor releases may add findings, so document rule additions in CHANGELOG and keep rule IDs stable. Removing/renaming a rule or changing JSON schema fields is a major change.

## I. GitHub Action (`action.yml`, Phase 5)
```yaml
name: "MCP Audit"
description: "Scan MCP server configs for security risks"
inputs:
  paths: { description: "Files/dirs to scan", default: "" }
  fail-on: { description: "Severity threshold", default: "high" }
  version: { description: "mcp-audit version", default: "latest" }
  sarif-file: { description: "SARIF output path", default: "mcp-audit.sarif" }
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
      with: { node-version: 20 }
    - shell: bash
      run: npx --yes mcp-audit@${{ inputs.version }} scan ${{ inputs.paths }} --no-user --fail-on ${{ inputs.fail-on }} -f sarif -o ${{ inputs.sarif-file }}
```
Users add a `github/codeql-action/upload-sarif` step afterwards.

## J. pre-commit hook (`.pre-commit-hooks.yaml`)
```yaml
- id: mcp-audit
  name: mcp-audit
  entry: npx --yes mcp-audit scan --no-user --fail-on high
  language: system
  files: '(^|/)(\.mcp\.json|mcp\.json|mcp_config\.json|claude_desktop_config\.json)$'
  pass_filenames: true
```
