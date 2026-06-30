---
name: tower-it-compliance
description: Check and improve software artifacts against China Tower IT Software Development Specification 2026. Use when reviewing or modifying Java/Spring/RuoYi projects, frontend JavaScript/Vue/Uni-app code, database SQL/design, API/microservice design, Web security, logging, performance, UI/UE, or big-screen dashboards for compliance with 中国铁塔股份有限公司IT软件开发规范（2026版） and its five annexes.
---

# China Tower IT Compliance

## Workflow

1. Identify the artifact type: backend Java/Spring, frontend JavaScript/Vue/Uni-app, database/SQL, API/microservice design, security/performance, UI/UE, or big-screen dashboard.
2. Read `references/spec-summary.md` for the relevant compliance checklist before editing.
3. Run `scripts/tower_compliance_scan.py <repo-or-file>` for a fast static scan when source code is available.
4. Prioritize mandatory findings: hardcoded secrets, unsafe SQL, missing input validation, weak authentication/authorization, unsafe upload/download, missing logging, resource leaks, and nonconforming naming/structure.
5. Modify code minimally and consistently with the existing project; do not rename public APIs, tables, or fields unless required and safe.
6. Validate with the project’s existing tests, build, formatter, or linter when practical.
7. Report remaining manual-review items separately from fixed issues.

## Compliance Priorities

- **Security first**: Validate input, encode output, prevent SQL injection and XSS, enforce authentication/authorization, protect sensitive data, avoid exposing stack traces, and keep secrets out of code.
- **Java backend**: Follow package/import/class/member/method organization, descriptive camelCase/PascalCase names, single-purpose classes/methods, thread-pool usage, resource cleanup, logging, and transaction boundaries.
- **Frontend**: Use UTF-8, clear naming, consistent directory layout, safe DOM rendering, guarded downloads/uploads, user feedback, reusable components, and performance-conscious loops/string handling.
- **Database**: Use standardized names, primary keys, indexes for query paths, explicit column lists, pagination for large lists, safe transaction scope, and database-independent SQL where possible.
- **API/microservice**: Use layered Controller/Service/DAO boundaries, documented interfaces, DTO/VO/entity separation, token-based gateway authentication, whitelist review, and service degradation/fallback where applicable.
- **UI/UE and big screen**: Preserve consistency, reduce unnecessary navigation, provide closed-loop returns, use China Tower identity where required, ensure complete text/data display, consistent fields, responsive layout, and permission-controlled drill-down/export.

## Scanner

Run the bundled scanner for quick evidence gathering:

```bash
python <skill-dir>/scripts/tower_compliance_scan.py <repo-or-file> --format text
python <skill-dir>/scripts/tower_compliance_scan.py <repo-or-file> --format json
```

Treat scanner results as heuristics, not a full audit. Confirm each finding in context before changing code.

## References

- Use `references/spec-summary.md` for extracted规范要点 and manual review checklist.
- Use the original 2026 documents when a rule is ambiguous or the work requires exact wording.

## Claude Code Compatibility

- Use `CLAUDE.md` as the Claude Code project instruction entry point.
- Use `.claude/commands/tower-compliance.md` as a Claude Code slash-command style workflow for scanning, triage, and safe fixes.
- Keep `agents/openai.yaml` for Codex/OpenAI clients; Claude Code can ignore it.
