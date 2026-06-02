# Security Agent

A collection of specialized AI agents for security analysis and vulnerability detection.

## Agents

### `java-security`

**File:** [.github/agents/java-security.agent.md](.github/agents/java-security.agent.md)

A Java security expert agent covering OWASP Top 10, CWE weaknesses, and JVM-specific attack surfaces. Use it to audit Java/Spring/Jakarta EE codebases for security issues.

**Triggers:** Java code security audits, dependency CVE scanning, hardcoded credential detection, or reviewing authentication and cryptography implementations.

**Vulnerability coverage:**

| Category | Examples |
|---|---|
| Injection | SQL, Command, LDAP, XXE, Log4Shell, SpEL, Template |
| Broken Auth | Hardcoded secrets, weak hashing, JWT misuse, insecure sessions |
| Cryptography | Weak algorithms (DES/MD5/RC4), disabled TLS verification, insecure `Random` |
| Access Control | Path traversal, missing `@PreAuthorize`, insecure file uploads |
| Deserialization | `ObjectInputStream`, `XMLDecoder`, Jackson polymorphic typing |
| SSRF | `RestTemplate`, `WebClient`, `new URL()` with user-controlled input |
| Spring / Jakarta EE | CSRF/CORS disabled, Actuator exposure, open redirect, mass assignment |

**Workflow:**
1. Scope definition (project / module / file / vulnerability class)
2. Dependency scan (OWASP Dependency Check, OSS Index)
3. Static analysis (Semgrep, SpotBugs + FindSecBugs)
4. Targeted grep passes
5. Contextual data-flow review
6. Severity-ranked report with CWE/OWASP references
7. **Phase 1** — Auto-apply zero-risk fixes
8. **Phase 2** — Remove unused code and dependencies
9. **Phase 3** — Propose an upgrade plan for everything that needs attention

### Remediation phases

The agent always remediates in order — it will not skip ahead.

#### Phase 1 — Auto-fix (applied immediately)

Changes that are safe to apply without review:

- **Patch / minor dependency bumps** — same major version, no API changes in changelog, CVE resolved. Applied via `mvn versions:use-next-releases`, build verified green after each batch.
- **Mechanical one-liner code fixes** — `new Random()` → `SecureRandom`, `MD5`/`SHA-1` → `SHA-256`, `setHttpOnly(false)` → `true`, missing XXE feature flags. Single call-site, no logic change.

The agent will not auto-apply: major version bumps, BOM-managed transitive deps, or any fix that touches business logic or spans multiple call sites.

#### Phase 2 — Dead code & unused dependency removal (applied immediately)

- Unused dependencies confirmed by `mvn dependency:analyze` + zero `import` references in source.
- Dead classes and methods confirmed by `vscode_listCodeUsages` + grep (guards against reflection-based loading).
- Unused imports flagged by the compiler.

Build is verified green after each removal.

#### Phase 3 — Upgrade plan (proposed, not applied)

For everything that could not be auto-fixed — major version migrations, CVEs requiring API changes, architectural security fixes — the agent produces a structured plan:

```
UPGRADE: <library or component>
Current:  <groupId:artifactId:version>
Target:   <groupId:artifactId:version>
CVE/CWE:  <identifier>
Risk:     <what can break>
Effort:   XS / S / M / L / XL
Steps:    1. … 2. … 3. …
Blockers: <prerequisites>
```

Followed by a prioritised execution table ordered by CVE severity → CVSS score → effort. Nothing in this phase is applied without explicit approval.

## Usage

### Prerequisites

- [VS Code](https://code.visualstudio.com/) with the [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) and [GitHub Copilot Chat](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot-chat) extensions installed.
- A GitHub Copilot subscription (Individual, Business, or Enterprise).

### Setup

1. Copy or clone this repository so the `.github/agents/` folder is present at the root of your Java project.
2. Open the project in VS Code. Copilot automatically discovers any `*.agent.md` files under `.github/agents/`.

### Invoking the agent

Open Copilot Chat (`Ctrl+Alt+I` / `Cmd+Alt+I`) and mention the agent by name:

```
@java-security audit this project for SQL injection and hardcoded credentials
```

```
@java-security scan the AuthService class for JWT vulnerabilities
```

```
@java-security run a full dependency CVE check
```

The agent will clarify scope if needed, then execute its analysis workflow: dependency scan → static analysis → targeted grep passes → data-flow review → severity-ranked report with fix suggestions.

### Example prompts

| Goal | Prompt |
|---|---|
| Full project audit | `@java-security perform a full OWASP Top 10 audit of this project` |
| Specific vulnerability | `@java-security check for deserialization vulnerabilities` |
| Single file review | `@java-security review UserController.java for injection risks` |
| Dependency CVEs | `@java-security scan pom.xml for known CVEs` |
| Apply fixes | `@java-security fix the weak crypto issues you found` |
| Full remediation | `@java-security audit and remediate this project` |
| Upgrade plan only | `@java-security give me an upgrade plan for all outdated and vulnerable dependencies` |
| Cleanup only | `@java-security remove all unused dependencies and dead code` |

### How agent files work

Each agent is a Markdown file with a YAML frontmatter block that declares its `name`, `description`, and the `tools` it is allowed to use. Copilot uses the `description` field to automatically suggest the agent when your prompt matches its area of expertise — you can also invoke it explicitly with `@<name>` at any time.

## Reporting Format

Each finding is reported as:

```
[SEVERITY] CWE-XXX — Short Title
File: src/main/java/com/example/Foo.java:42
Description: why this is dangerous
Evidence: relevant code snippet
Fix: concrete remediation
CVSS: score (if known)
References: OWASP A0X:2021, CWE-XXX
```

Severity scale: **CRITICAL** → **HIGH** → **MEDIUM** → **LOW**
