---
description: Review and fix a project against China Tower IT Software Development Specification 2026
argument-hint: [target path] [optional focus]
---

# Tower Compliance Review

Target: `$ARGUMENTS`

Use this repository as the compliance pack. Follow these steps:

1. Read `SKILL.md` to understand the review workflow.
2. Read `references/spec-summary.md`; focus on sections matching the target project, especially Java backend, frontend, database/SQL, microservice design, quality/security, UI/UE, and big-screen rules.
3. If `$ARGUMENTS` contains a target path, run:

```bash
python scripts/tower_compliance_scan.py "$ARGUMENTS" --format text
```

If the argument includes both a path and extra focus text, infer the path first. If unclear, ask for the target path.

4. Triage scanner findings:
   - Remove obvious false positives from Maven property placeholders, schema URLs, generated/minified vendor files, and documentation-only examples.
   - Keep real findings involving credentials, SQL injection, unsafe upload/download, exception handling, logging, authorization, CORS, and HTTP transport.
5. Report counts by severity and rule, top affected files, and the highest-risk actionable items.
6. If asked to fix, apply minimal changes in this order:
   - Externalize credentials and connection strings.
   - Replace unsafe SQL concatenation and unsafe MyBatis `${}` with parameters or strict whitelist validation.
   - Add upload/download validation and authorization checks.
   - Replace `printStackTrace`/console output/swallowed exceptions with structured logging and unified exception handling.
   - Tighten anonymous routes, whitelists, CORS, and HTTP usage.
7. Run available targeted tests/build checks after modifications and summarize remaining manual-review items.

Never treat the scanner as a complete audit; combine it with manual code review against `references/spec-summary.md`.

