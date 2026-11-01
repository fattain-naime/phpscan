Below is a ground-up rewrite — v2 of `phpscan.py`. It keeps the name and purpose but replaces regex-only grepping with a taint-tracking engine, a rule/plugin system, CI-grade reporting (SARIF, JUnit, baseline suppression, incremental cache), and exit-code semantics.

**What actually changed, concretely:**

- **Taint engine.** Variables assigned from `$_GET`/`$_POST`/`php://input`/headers are tracked to sinks, with sanitizer clearing (`(int)`, `htmlspecialchars`, `escapeshellarg`, `mysqli_real_escape_string`, `basename`, `filter_var`, …). Findings name the tainted variable and its origin, and get a confidence score bump.
- **Secrets.** Shannon-entropy scoring over assignment-shaped literals plus signatures for AWS/GitHub/Stripe/Slack/private keys/JWTs, with placeholder filtering.
- **60+ rules** across RCE, deserialization, LFI, SQLi, XSS, XXE, SSRF, LDAP, uploads, sessions, crypto, CSRF, type juggling, and config smells — each with CWE and remediation text.
- **Reporting.** SARIF 2.1.0 (fingerprinted, works in GitHub code scanning), JUnit for CI, Markdown/HTML for humans, JSON for tooling, and text with code frames.
- **Workflow.** Baselines with fingerprints, incremental cache keyed on mtime+size, `--git-diff origin/main` for PR-only scans, severity remapping, tag filtering, per-rule suppression, rule packs (JSON/YAML) and Python plugins.
- **Engineering.** Threaded, binary/huge-file guards, `.git`/`vendor`-style skip list, dedupe, deterministic ordering, real exit codes, `--list-rules`.

Typical CI invocation:

```bash
phpscan src/ --min-severity medium --format sarif -o phpscan.sarif --fail-on high --cache
```

If you paste the original file, I'll fold its CLI surface and any custom checks into this so existing scripts and suppressions keep working.
