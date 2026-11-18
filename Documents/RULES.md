# Rule Catalog

IDs are stable. Severity is the default and can be lowered via config. "Static" rules run on config files; "Tool" rules run on tool definitions (`--tools` or `--introspect`).

| ID | Title | Sev | Phase |
|---|---|---|---|
| MCPA-SEC-001 | Hardcoded secret in env, args, or headers | critical | 2 |
| MCPA-SEC-002 | Secret embedded in URL (query or userinfo) | high | 2 |
| MCPA-SEC-003 | Remote server over plaintext HTTP | high | 2 |
| MCPA-SEC-004 | Unpinned package run via npx/uvx/pipx/bunx/dlx | medium | 2 |
| MCPA-SEC-005 | Package pinned to `latest`/`@next`/branch/floating range | medium | 2 |
| MCPA-SEC-006 | Shell interpreter used as command (`sh -c`, `bash -c`, `cmd /c`, `powershell -c`) | high | 2 |
| MCPA-SEC-007 | Download-and-execute pattern (`curl|sh`, `wget|bash`, `iex (irm ...)`) | critical | 2 |
| MCPA-SEC-008 | Filesystem access too broad (`/`, `~`, drive root, `$HOME`, `C:\`) | high | 2 |
| MCPA-SEC-009 | Dangerous Docker flags (`--privileged`, `docker.sock` mount, `--network host`, `-v /:/`) | high | 2 |
| MCPA-SEC-010 | Possible typosquat of known MCP/npm package | high | 4 |
| MCPA-SEC-014 | Blanket auto-approve (`autoApprove: ["*"]`, `alwaysAllow` all, `true`) | high | 2 |
| MCPA-SEC-015 | Config containing secrets is group/world-readable (POSIX) | medium | 2 |
| MCPA-SEC-016 | Remote URL is raw IP, tunnel host (ngrok, trycloudflare, localtunnel), or non-local http | medium | 4 |
| MCPA-TOOL-001 | Prompt-injection phrasing in tool description | high | 4/6 |
| MCPA-TOOL-002 | Hidden/invisible Unicode in tool name or description | high | 4/6 |
| MCPA-TOOL-003 | Tool name collision/shadowing across servers | medium | 4/6 |
| MCPA-TOOL-004 | Tool description instructs reading sensitive paths or exfiltration | critical | 6 |

## Rule details

### MCPA-SEC-001 Hardcoded secret
- **Detect:** run `secrets.detect()` (ARCHITECTURE §8) over every `env` value, every `args` element, every `headers` value.
- **Safe:** env references like `${GITHUB_TOKEN}`, `${input:token}`.
- **Remediation:** move to an env var or the client's secret input mechanism; rotate the exposed secret.
- **Fixtures bad:** `"env":{"GITHUB_TOKEN":"ghp_<36 chars>"}`, `"args":["--api-key","sk-ant-..."]`. **Good:** `"env":{"GITHUB_TOKEN":"${GITHUB_TOKEN}"}`, placeholder `"your-token-here"`.

### MCPA-SEC-003 Plaintext HTTP
- **Detect:** `url` starts with `http://` and host is not `localhost`, `127.0.0.1`, `::1`.
- **Remediation:** use HTTPS.

### MCPA-SEC-004 / 005 Unpinned packages
- **Detect:** command basename in `{npx, bunx, pnpm dlx, yarn dlx, uvx, pipx}` (handle `pnpm`/`yarn` with `dlx` arg). First non-flag arg is the package spec.
  - 004: spec has no version (`pkg`, `@scope/pkg`) or only `-y` style flags with no spec version.
  - 005: version is `latest`, `next`, `*`, a git branch ref, or a range (`^`, `~`, `>`).
- **Safe:** exact semver (`pkg@1.2.3`), or sha/tag for git deps.
- **Remediation:** pin an exact version; consider verifying integrity.
- **Note:** `-y`/`--yes` alone is info-level context, not a separate finding.

### MCPA-SEC-006 Shell wrapper
- **Detect:** command basename in `{sh, bash, zsh, fish, cmd, cmd.exe, powershell, pwsh}` with `-c`/`/c`/`-Command`.
- **Remediation:** invoke the binary directly with `args`; avoid shell string composition.

### MCPA-SEC-007 Download and execute
- **Detect:** joined command line matches `/(curl|wget)[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)/`, or `iex`/`Invoke-Expression` with `irm`/`iwr`/`DownloadString`.

### MCPA-SEC-008 Broad filesystem
- **Detect:** server looks like filesystem server (package/binary name contains `server-filesystem` or `filesystem`) OR any arg is an absolute path; flag args equal to `/`, `~`, `$HOME`, `${HOME}`, `C:\`, `C:/`, the user's actual home directory, or a path with <=1 segment (e.g. `/Users`, `/home`).
- **Remediation:** scope to a specific project directory.

### MCPA-SEC-009 Docker flags
- **Detect:** command `docker`/`podman` with `run` and any of: `--privileged`, `--network=host`/`--net=host`, `-v/--volume` containing `/var/run/docker.sock`, mounting `/` or `~`/home root, `--cap-add=ALL`, `--pid=host`.

### MCPA-SEC-010 Typosquat
- **Detect:** Levenshtein distance 1-2 (or common swaps: `-`/`_`, doubled letters, scope removal) from an embedded list of well-known MCP packages (`@modelcontextprotocol/server-*`, `mcp-server-*` popular ones) and the name is not on the list itself. Respect `trustedPackages` config.
- Keep the list in `src/rules/data/known-packages.ts` so it is easy to update.

### MCPA-SEC-014 Auto-approve
- **Detect:** keys `autoApprove`, `alwaysAllow`, `autoapprove`, `trust: true`; value is `true`, `"*"`, or an array containing `"*"`. Lower severity to medium if the array lists specific read-only-looking tools.

### MCPA-SEC-015 File permissions
- **Detect (POSIX only):** file mode has group or other read bit AND file contains any non-reference secret-like values. Skip on Windows.

### MCPA-SEC-016 Risky remote
- **Detect:** host is IPv4/IPv6 literal (non-loopback) or ends with `ngrok.io`, `ngrok-free.app`, `trycloudflare.com`, `loca.lt`, `serveo.net`.

### MCPA-TOOL-001 Prompt-injection phrasing
- **Detect (case-insensitive) in description:** `ignore (all )?(previous|prior) instructions`, `do not (tell|inform|mention).*user`, `<important>`, `before (using|calling) this tool.*(read|send|include)`, `system prompt`, `you must (also )?(call|use)`, instructions to call *other* tools, base64 blobs >200 chars.
- Description length >2000 chars adds a low-severity note.

### MCPA-TOOL-002 Invisible Unicode
- **Detect:** code points in zero-width (U+200B-U+200F), bidi controls (U+202A-U+202E, U+2066-U+2069), tag chars (U+E0000-U+E007F), BOM mid-string.

### MCPA-TOOL-003 Shadowing
- **Detect:** same tool name exposed by 2+ servers, or a name that differs only by case/punctuation from a tool of another server.

### MCPA-TOOL-004 Exfiltration instructions
- **Detect:** description mentions reading `~/.ssh`, `.env`, `id_rsa`, `credentials`, `~/.aws`, `~/.config` combined with send/post/upload/include-in-parameter wording.

## Authoring a new rule (checklist)
1. Add `src/rules/<id>-<slug>.ts` exporting a `Rule`; register in `rules/index.ts`.
2. Add good and bad fixtures; >=3 positive and >=3 negative tests.
3. Add docs text (`docs` field) with *why it matters*, *how to fix*, *how to ignore*.
4. Update this table and CHANGELOG.
5. Confirm evidence is redacted.
