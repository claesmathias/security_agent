# Security Agent

A collection of specialized AI agents for security analysis, vulnerability detection, and automated remediation. Each agent follows the same three-phase remediation workflow: auto-fix zero-risk issues first, remove unused code and resources second, then propose a structured upgrade plan for everything that needs human review.

## Agents

### `java-security`

**File:** [.github/agents/java-security.agent.md](.github/agents/java-security.agent.md)

Audits Java/Spring/Jakarta EE codebases for security vulnerabilities across OWASP Top 10 and CWE top weaknesses.

| Category | Examples |
|---|---|
| Injection | SQL, Command, LDAP, XXE, Log4Shell, SpEL, Template |
| Broken Auth | Hardcoded secrets, weak hashing, JWT misuse, insecure sessions |
| Cryptography | Weak algorithms (DES/MD5/RC4), disabled TLS verification, insecure `Random` |
| Access Control | Path traversal, missing `@PreAuthorize`, insecure file uploads |
| Deserialization | `ObjectInputStream`, `XMLDecoder`, Jackson polymorphic typing |
| SSRF | `RestTemplate`, `WebClient`, `new URL()` with user-controlled input |
| Spring / Jakarta EE | CSRF/CORS disabled, Actuator exposure, open redirect, mass assignment |

**Tooling:** OWASP Dependency Check, OSS Index, Semgrep, SpotBugs + FindSecBugs

---

### `iac-security`

**File:** [.github/agents/iac-security.agent.md](.github/agents/iac-security.agent.md)

Audits cloud Infrastructure as Code for misconfigurations, insecure defaults, and compliance gaps across all major providers and formats.

**Supported formats:** Terraform · AWS CloudFormation · Azure Bicep/ARM · Google Cloud Deployment Manager · Kubernetes manifests · Helm charts · Ansible playbooks

| Category | Examples |
|---|---|
| IAM & Permissions | Wildcard actions/resources, overly permissive assume-role, missing MFA conditions |
| Network & Exposure | Open security groups (`0.0.0.0/0`), public RDS/S3, SSH/RDP open to internet |
| Encryption | Unencrypted S3/EBS/RDS/SQS, HTTP listeners, weak TLS policies |
| Logging & Monitoring | CloudTrail disabled, no VPC flow logs, no S3/ALB access logs |
| Secrets | Hardcoded passwords/API keys, plaintext Kubernetes Secrets, sensitive outputs |
| Kubernetes & Containers | Privileged containers, root user, no resource limits, no network policies, RBAC wildcards |
| Terraform-Specific | Unencrypted state backend, unpinned provider versions, missing `prevent_destroy` |

**Tooling:** checkov, trivy, tfsec, kube-score, cfn-nag

---

## Three-Phase Remediation Workflow

Both agents always remediate in this order and will not skip ahead.

### Phase 1 — Auto-fix (applied immediately)

Changes safe to apply without human review. The build or plan is verified green after every batch.

**`java-security`**
- Patch/minor dependency bumps — same major version, CVE resolved, no API changes in changelog
- Mechanical one-liner fixes — `new Random()` → `SecureRandom`, `MD5` → `SHA-256`, `setHttpOnly(false)` → `true`, missing XXE feature flags

**`iac-security`**
- Flag flips — `encrypted = true`, `enable_logging = true`, `block_public_acls = true`, `sensitive = true` on outputs
- Kubernetes security context — `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities: drop: [ALL]`, `automountServiceAccountToken: false`
- Missing resource tags, unpinned provider version constraints

**Stop criteria (never auto-applied):** major version bumps, changes that force resource replacement, fixes that touch business logic or span multiple call sites, anything that affects live production traffic.

### Phase 2 — Remove unused code and resources (applied immediately)

Each removal is verified with a build/plan/dry-run before committing.

**`java-security`** — unused dependencies (`mvn dependency:analyze`), dead classes and methods (`vscode_listCodeUsages` + grep), unused imports (compiler warnings)

**`iac-security`** — orphaned Terraform resources (zero cross-references), unused IAM roles/security groups (AWS CLI last-used data), orphaned Kubernetes ConfigMaps, Secrets, and ServiceAccounts

### Phase 3 — Upgrade plan (proposed, not applied)

For anything that cannot be fixed safely — major version migrations, resource replacements, architectural changes, IAM rewrites, network redesigns. Nothing in this phase is applied without explicit approval.

Output format:

```
UPGRADE: <library, resource, or component>
File:     <path>
Current:  <current version or state>
Target:   <desired version or state>
CVE/CWE/CIS: <identifier>
Risk:     <what can break>
Effort:   XS / S / M / L / XL
Steps:    1. … 2. … 3. …
Blockers: <prerequisites>
```

Followed by a prioritised execution table ordered by severity → CVSS/CIS score → effort.

---

## Usage

### Prerequisites

- [VS Code](https://code.visualstudio.com/) with the [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) and [GitHub Copilot Chat](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot-chat) extensions installed
- A GitHub Copilot subscription (Individual, Business, or Enterprise)

### Setup

1. Copy or clone this repository so the `.github/agents/` folder is present at the root of your project.
2. Open the project in VS Code — Copilot automatically discovers any `*.agent.md` files under `.github/agents/`.

### Invoking an agent

Open Copilot Chat (`Ctrl+Alt+I` / `Cmd+Alt+I`) and prefix your request with the agent name:

```
@java-security audit this project for SQL injection and hardcoded credentials
```

```
@iac-security audit all Terraform modules for IAM and encryption issues
```

The agent will clarify scope if needed, then run its analysis workflow and remediation phases automatically.

### Example prompts

| Agent | Goal | Prompt |
|---|---|---|
| `@java-security` | Full OWASP audit | `perform a full OWASP Top 10 audit of this project` |
| `@java-security` | Specific vulnerability | `check for deserialization vulnerabilities` |
| `@java-security` | Single file | `review UserController.java for injection risks` |
| `@java-security` | Dependency CVEs | `scan pom.xml for known CVEs` |
| `@java-security` | Full remediation | `audit and remediate this project` |
| `@java-security` | Upgrade plan only | `give me an upgrade plan for all outdated and vulnerable dependencies` |
| `@java-security` | Cleanup only | `remove all unused dependencies and dead code` |
| `@iac-security` | Full IaC audit | `audit and remediate this Terraform repo` |
| `@iac-security` | Specific check | `find all unencrypted storage resources` |
| `@iac-security` | Kubernetes | `review all Kubernetes manifests for CIS benchmark violations` |
| `@iac-security` | Upgrade plan | `give me an upgrade plan for all high-risk infrastructure changes` |
| `@iac-security` | Secrets scan | `find all hardcoded secrets and open security groups` |

### How agent files work

Each agent is a Markdown file under `.github/agents/` with a YAML frontmatter block declaring its `name`, `description`, and the `tools` it may use. Copilot uses the `description` field to automatically suggest the right agent when your prompt matches its expertise — you can also invoke any agent explicitly with `@<name>` at any time.

---

## Reporting Format

Each finding is reported as:

```
[SEVERITY] CWE-XXX / CIS-X.X — Short Title
File: src/main/java/com/example/Foo.java:42
Description: one sentence on why this is dangerous
Evidence: relevant code or config snippet
Fix: concrete remediation with example
CVSS: score (if known)
References: OWASP A0X:2021 / CIS Benchmark X.X, CWE-XXX, CVE-XXXX-XXXX
```

Severity scale: **CRITICAL** (RCE, auth bypass, public data exposure) → **HIGH** (unencrypted data, logging disabled, data exfil) → **MEDIUM** (info leak, overly broad access) → **LOW** (defence-in-depth, missing tags)
