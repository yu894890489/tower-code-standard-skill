#!/usr/bin/env python3
"""Heuristic scanner for China Tower IT software compliance checks."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


TEXT_SUFFIXES = {
    ".java",
    ".xml",
    ".sql",
    ".properties",
    ".yml",
    ".yaml",
    ".json",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".html",
    ".css",
    ".scss",
    ".md",
}

SKIP_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "node_modules",
    "target",
    "build",
    "dist",
    "out",
    ".gradle",
    ".mvn",
    "coverage",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    category: str
    message: str
    pattern: re.Pattern[str]
    suffixes: set[str] | None = None


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    severity: str
    category: str
    message: str
    snippet: str


RULES = [
    Rule(
        "SEC001",
        "high",
        "secret",
        "疑似硬编码密码、密钥或令牌；应改为配置中心、环境变量或密钥管理，并避免入库。",
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
    ),
    Rule(
        "SEC002",
        "high",
        "database",
        "疑似 JDBC/数据库连接串硬编码；应外置配置并保护账号口令。",
        re.compile(r"(?i)jdbc:[a-z0-9:]+://|mongodb://|redis://"),
    ),
    Rule(
        "SEC003",
        "high",
        "sql-injection",
        "疑似字符串拼接 SQL；应使用参数化查询、ORM 安全绑定或 MyBatis #{}。",
        re.compile(r"(?i)(select|insert|update|delete)\s+[^;\n]*(\+|\$\{|%s|format\()"),
        {".java", ".xml", ".sql", ".js", ".ts"},
    ),
    Rule(
        "SEC004",
        "high",
        "sql-injection",
        "MyBatis `${}` 存在注入风险；除受控白名单排序/表名外应改为 `#{}`。",
        re.compile(r"\$\{[^}]+}"),
        {".xml"},
    ),
    Rule(
        "SEC005",
        "high",
        "xss",
        "疑似不安全 HTML 注入；应净化或按上下文编码后输出。",
        re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|v-html|dangerouslySetInnerHTML)\b"),
        {".js", ".jsx", ".ts", ".tsx", ".vue", ".html"},
    ),
    Rule(
        "SEC006",
        "medium",
        "transport",
        "发现 HTTP 明文地址；生产链路应优先使用 HTTPS 或受控内网传输。",
        re.compile(r"http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"),
    ),
    Rule(
        "SEC007",
        "medium",
        "cors",
        "疑似宽泛跨域配置；应限制可信来源、方法和凭证策略。",
        re.compile(r"(?i)(allowedOriginPatterns|allowedOrigins|Access-Control-Allow-Origin).*(\*|all)"),
    ),
    Rule(
        "SQL001",
        "medium",
        "database",
        "发现 SELECT *；生产代码建议显式列名，减少冗余和兼容风险。",
        re.compile(r"(?i)\bselect\s+\*\s+from\b"),
        {".java", ".xml", ".sql"},
    ),
    Rule(
        "LOG001",
        "medium",
        "logging",
        "发现控制台输出；后端应使用统一日志框架并控制敏感信息。",
        re.compile(r"\b(System\.out\.println|console\.log|console\.error)\s*\("),
        {".java", ".js", ".jsx", ".ts", ".tsx", ".vue"},
    ),
    Rule(
        "ERR001",
        "medium",
        "exception",
        "发现 printStackTrace；应使用统一日志和异常处理，避免泄露内部细节。",
        re.compile(r"\.printStackTrace\s*\("),
        {".java"},
    ),
    Rule(
        "ERR002",
        "medium",
        "exception",
        "疑似吞异常；应记录上下文、转换业务异常或明确处理。",
        re.compile(r"catch\s*\([^)]*\)\s*\{\s*(//[^\n]*)?\s*\}"),
        {".java", ".js", ".ts"},
    ),
    Rule(
        "UPLOAD001",
        "medium",
        "upload",
        "发现上传入口线索；需人工确认文件类型、大小、路径、鉴权和病毒/内容校验。",
        re.compile(r"(?i)\b(MultipartFile|upload|fileUpload|el-upload|uni\.uploadFile)\b"),
    ),
    Rule(
        "AUTH001",
        "medium",
        "authorization",
        "发现白名单/匿名访问线索；需人工确认最小化、可追踪并定期复核。",
        re.compile(r"(?i)(permitAll|anonymous|ignoreUrls|white[-_]?list|whitelist|无需认证|免认证)"),
    ),
]


def iter_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        if target.suffix.lower() in TEXT_SUFFIXES:
            yield target
        return

    for root, dirs, files in os.walk(target):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        root_path = Path(root)
        for file_name in files:
            path = root_path / file_name
            if path.suffix.lower() in TEXT_SUFFIXES:
                yield path


def read_text(path: Path) -> str | None:
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
        except OSError:
            return None
    return None


def scan_file(path: Path, root: Path) -> list[Finding]:
    text = read_text(path)
    if text is None:
        return []

    findings: list[Finding] = []
    suffix = path.suffix.lower()
    rel_path = str(path if root.is_file() else path.relative_to(root))

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "#")):
            continue
        for rule in RULES:
            if rule.suffixes is not None and suffix not in rule.suffixes:
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        path=rel_path,
                        line=line_number,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        message=rule.message,
                        snippet=stripped[:180],
                    )
                )
    return findings


def scan(target: Path) -> list[Finding]:
    root = target.resolve()
    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(scan_file(path.resolve(), root))
    return findings


def print_text(findings: list[Finding]) -> None:
    if not findings:
        print("No heuristic compliance findings found.")
        return

    order = {"high": 0, "medium": 1, "low": 2}
    for finding in sorted(findings, key=lambda item: (order.get(item.severity, 9), item.path, item.line)):
        print(f"[{finding.severity.upper()}] {finding.rule_id} {finding.path}:{finding.line}")
        print(f"  {finding.message}")
        print(f"  {finding.snippet}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan source files for China Tower IT compliance heuristics.")
    parser.add_argument("target", help="Repository, directory, or file to scan")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        return 2

    findings = scan(target)
    if args.format == "json":
        print(json.dumps([asdict(finding) for finding in findings], ensure_ascii=False, indent=2))
    else:
        print_text(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

