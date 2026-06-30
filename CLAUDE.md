# China Tower IT Compliance Skill for Claude Code

Use this repository as a Claude Code-compatible compliance pack for reviewing and fixing projects against 中国铁塔股份有限公司 IT 软件开发规范（2026版）.

## How to Use

When asked to check China Tower IT compliance, do the following:

1. Read `SKILL.md` for the workflow and priorities.
2. Read `references/spec-summary.md` for the relevant checklist sections.
3. Run the scanner when source code is available:

```bash
python scripts/tower_compliance_scan.py <repo-or-file> --format text
```

Use JSON when you need machine-readable output:

```bash
python scripts/tower_compliance_scan.py <repo-or-file> --format json
```

4. Treat scanner output as heuristic evidence. Confirm each finding in context before changing code.
5. Prioritize fixes in this order:
   - Hardcoded credentials, keys, tokens, and connection strings.
   - SQL injection risks from Java string concatenation or MyBatis `${}`.
   - Unsafe upload/download paths, file type checks, size checks, and authorization.
   - `printStackTrace`, console output, swallowed exceptions, and sensitive logging.
   - Overbroad `@Anonymous`, whitelist, CORS, HTTP, and gateway exposure.
6. Modify code minimally, preserve existing architecture, and run available tests/builds after changes.

## Claude Code Slash Command

This repository includes `.claude/commands/tower-compliance.md` for Claude Code slash-command style usage. Copy or keep this repo in a place Claude Code can read, then invoke the command/prompt with the target project path.

Example prompt:

```text
Use this compliance pack to scan C:\path\to\project, summarize high-risk findings, and fix safe high-risk issues first.
```

## Compatibility Notes

- `agents/openai.yaml` is used by Codex/OpenAI clients and is ignored by Claude Code.
- `CLAUDE.md`, `.claude/commands/tower-compliance.md`, `SKILL.md`, `references/`, and `scripts/` are usable from Claude Code.
- The scanner requires Python 3.10+ and uses only the Python standard library.

