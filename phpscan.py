#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phpscan.py v2.0.0 — advanced PHP static application security scanner.

Highlights
----------
* Intraprocedural taint tracking: user-input sources -> dangerous sinks,
  with sanitizer awareness ((int), escapeshellarg, htmlspecialchars, ...).
* 60+ built-in rules across OWASP categories + Shannon-entropy secret
  detection with known-token signatures.
* Reporting: text (code frames), JSON, SARIF 2.1.0, Markdown, HTML, JUnit.
* Baselines (fingerprint suppression), incremental scan cache, git-diff
  mode for pull-request scanning.
* Rule packs (JSON/YAML) and Python plugins, severity remapping, per-rule
  suppression, multi-threaded file processing, CI exit codes.

Dependency-free (stdlib only). Optional: PyYAML for .yaml rule packs.

Exit codes: 0 clean | 1 findings >= --fail-on | 2 usage/IO | 3 internal
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import html
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

VERSION = "2.0.0"
CACHE_NAME = ".phpscan-cache.json"
CONFIG_NAMES = (".phpscan.json", "phpscan.json")

PHP_EXTS = {".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phps", ".inc", ".module", ".ctp"}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".idea", ".vscode", "__pycache__", ".phpscan"}

SEVERITY_WEIGHT = {"info": 1, "low": 2, "medium": 4, "high": 8, "critical": 16}
SEVERITY_RANK = {name: i for i, name in enumerate(("info", "low", "medium", "high", "critical"))}

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
ANSI = {
    "critical": "\033[1;95m", "high": "\033[1;91m", "medium": "\033[1;93m",
    "low": "\033[1;96m", "info": "\033[1;90m", "dim": "\033[2m",
    "bold": "\033[1m", "reset": "\033[0m", "path": "\033[1;94m",
}


def colorize(text: str, key: str) -> str:
    if not USE_COLOR or key not in ANSI:
        return text
    return f"{ANSI[key]}{text}{ANSI['reset']}"


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    id: str
    name: str
    severity: str
    patterns: tuple[str, ...]
    message: str
    remediation: str = ""
    cwe: str = ""
    tags: tuple[str, ...] = ()
    flags: int = re.IGNORECASE
    negative: str = ""
    kind: str = "pattern"

    def __post_init__(self) -> None:
        self.compiled = tuple(re.compile(p, self.flags) for p in self.patterns)
        self.negative_re = re.compile(self.negative, self.flags) if self.negative else None


@dataclass(frozen=True)
class TaintSink:
    rule_id: str
    name: str
    severity: str
    regex: re.Pattern
    message: str
    remediation: str
    cwe: str


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    path: str
    line: int
    code: str
    message: str
    remediation: str = ""
    cwe: str = ""
    column: int = 0
    tags: tuple[str, ...] = ()
    context: tuple[str, ...] = ()
    score: float = 0.0

    @property
    def fingerprint(self) -> str:
        norm = re.sub(r"\s+", " ", self.code.strip())
        blob = f"{self.path}|{self.rule_id}|{norm}"
        return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("context", None)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class Config:
    targets: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    min_severity: str = "low"
    fail_on: str | None = "high"
    threads: int = max(4, (os.cpu_count() or 4))
    max_file_size: int = 4 * 1024 * 1024
    follow_symlinks: bool = False
    severity_map: dict[str, str] = field(default_factory=dict)
    suppress: set[str] = field(default_factory=set)
    only_tags: set[str] = field(default_factory=set)
    secrets: bool = True
    entropy_threshold: float = 3.5
    cache: bool = False
    baseline: str | None = None
    write_baseline: str | None = None
    git_diff: str | None = None
    rules_dirs: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    output: str | None = None
    fmt: str = "text"
    quiet: bool = False
    stats: bool = False
    list_rules: bool = False


# --------------------------------------------------------------------------- #
# Built-in rules
# --------------------------------------------------------------------------- #

BUILTIN_RULES: list[Rule] = []


def _rule(**kw: Any) -> None:
    BUILTIN_RULES.append(Rule(**kw))


# --- code execution -------------------------------------------------------- #
_rule(id="PS001", name="eval() on dynamic data", severity="high",
      patterns=(r"\beval\s*\(",), message="eval() parses arbitrary PHP at runtime.",
      remediation="Prefer a whitelist, or eval only after strict validation.", cwe="CWE-95",
      tags=("rce", "owasp-a03"))
_rule(id="PS002", name="assert() with string argument", severity="medium",
      patterns=(r"\bassert\s*\(\s*['\"]",), message="String assert() is evaluated as PHP (pre-8.0).",
      remediation="Validate the expression or migrate to explicit comparisons.", cwe="CWE-95", tags=("rce",))
_rule(id="PS003", name="Shell execution function", severity="medium",
      patterns=(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",),
      message="Shell execution sink — verify arguments are escaped.",
      remediation="Wrap each argument in escapeshellarg().", cwe="CWE-78", tags=("rce", "owasp-a03"))
_rule(id="PS004", name="Backtick shell execution", severity="medium",
      patterns=(r"`[^`\n]+`",), message="Backtick operator runs a shell command.",
      remediation="Escape interpolated values with escapeshellarg().", cwe="CWE-78", tags=("rce",))
_rule(id="PS005", name="preg_replace /e modifier", severity="high",
      patterns=(r"preg_replace\s*\(\s*['\"][^'\"]*\/e",),
      message="The /e modifier evaluates the replacement as PHP.",
      remediation="Switch to preg_replace_callback().", cwe="CWE-95", tags=("rce",))
_rule(id="PS006", name="create_function()", severity="low",
      patterns=(r"\bcreate_function\s*\(",), message="create_function() is removed in PHP 8.",
      remediation="Use closures.", cwe="CWE-95", tags=("rce", "deprecated"))
_rule(id="PS007", name="Dynamic callable invocation", severity="medium",
      patterns=(r"\bcall_user_func(_array)?\s*\(\s*\$", r"\$[A-Za-z_]\w*\s*\(\s*\$"),
      message="Dynamic callable — the callee name comes from a variable.",
      remediation="Whitelist allowed callables.", cwe="CWE-470", tags=("rce",))

# --- object injection / deserialization ------------------------------------ #
_rule(id="PS010", name="unserialize() on untrusted data", severity="high",
      patterns=(r"\bunserialize\s*\(",), message="unserialize() can trigger magic-method gadget chains.",
      remediation="Pass ['allowed_classes' => [...]] and validate input.", cwe="CWE-502",
      tags=("deserialization", "owasp-a08"))
_rule(id="PS011", name="unserialize() of a cookie/session value", severity="high",
      patterns=(r"unserialize\s*\(\s*\$_(COOKIE|REQUEST|GET|POST)",),
      message="Client-controlled serialized payload.", remediation="Sign or HMAC the cookie.",
      cwe="CWE-502", tags=("deserialization",))
_rule(id="PS012", name="phar:// stream wrapper", severity="medium",
      patterns=(r"phar://",), message="phar:// deserializes metadata on access.",
      remediation="Treat phar metadata as untrusted.", cwe="CWE-502", tags=("deserialization",))

# --- file inclusion / traversal -------------------------------------------- #
_rule(id="PS020", name="Dynamic include/require", severity="high",
      patterns=(r"\b(include|include_once|require|require_once)\s*\(?\s*\$"),
      message="Include path is dynamic — LFI/RFI risk.",
      remediation="Resolve against a fixed base dir and whitelist names.", cwe="CWE-98",
      tags=("lfi", "owasp-a03"))
_rule(id="PS021", name="Include of a superglobal", severity="critical",
      patterns=(r"\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)",),
      message="Direct inclusion of request data.", remediation="basename() + whitelist.",
      cwe="CWE-98", tags=("lfi", "rfi"))
_rule(id="PS022", name="File read with variable path", severity="medium",
      patterns=(r"\b(file_get_contents|readfile|file|fopen|file_put_contents|unlink|copy|rename|mkdir|rmdir)\s*\(\s*\$",),
      message="Filesystem path from a variable.", remediation="Normalize and confine to a base path.",
      cwe="CWE-22", tags=("path-traversal",))
_rule(id="PS023", name="Zip extraction (zip-slip)", severity="medium",
      patterns=(r"->\s*extractTo\s*\(", r"\bZipArchive\b"), message="Archive entries may escape the target dir.",
      remediation="Verify entry names contain no '..' before extraction.", cwe="CWE-22", tags=("path-traversal",))

# --- SQL ------------------------------------------------------------------- #
_rule(id="PS030", name="SQL query built by concatenation", severity="high",
      patterns=(r"(mysqli?_query|->\s*(query|exec|prepare))\s*\(\s*[^;]*(\"|')\s*\.\s*\$",),
      message="String-concatenated SQL.", remediation="Use prepared statements with bound parameters.",
      cwe="CWE-89", tags=("sqli", "owasp-a03"))
_rule(id="PS031", name="SQL with interpolated variable", severity="high",
      patterns=(r"(mysqli?_query|->\s*(query|exec))\s*\(\s*[^;]*\"[^\"]*\$",),
      message="Double-quoted SQL interpolates variables.", remediation="Prefer placeholders.",
      cwe="CWE-89", tags=("sqli",))
_rule(id="PS032", name="Legacy mysql_* API", severity="low",
      patterns=(r"\bmysql_(query|connect|fetch|real_escape)",), message="mysql_* is removed in PHP 7.",
      remediation="Migrate to PDO or mysqli.", cwe="CWE-1104", tags=("sqli", "deprecated"))
_rule(id="PS033", name="ORDER BY / LIMIT from a variable", severity="medium",
      patterns=(r"(order\s+by|limit)\s+[^;\"']*\$",), message="Identifiers cannot be bound as parameters.",
      remediation="Whitelist column names and cast limits to int.", cwe="CWE-89", tags=("sqli",))

# --- output / XSS ---------------------------------------------------------- #
_rule(id="PS040", name="Short echo tag", severity="info",
      patterns=(r"<\?=",), message="Short echo tag — confirm output is escaped.",
      remediation="Wrap values in htmlspecialchars(..., ENT_QUOTES, 'UTF-8').", cwe="CWE-79", tags=("xss",))
_rule(id="PS041", name="Output into an inline event handler / script", severity="medium",
      patterns=(r"on(click|load|error|submit)\s*=\s*['\"][^'\"]*<\?php", r"<script[^>]*>[^<]*<\?php\s+echo"),
      message="JS/HTML context requires JS-aware escaping.", remediation="Use json_encode() for JS context.",
      cwe="CWE-79", tags=("xss",))
_rule(id="PS042", name="header() with dynamic value", severity="medium",
      patterns=(r"\bheader\s*\(\s*[^)]*\$",), message="Header injection / response splitting.",
      remediation="Strip CR/LF and validate redirect targets.", cwe="CWE-113", tags=("header-injection",))
_rule(id="PS043", name="Redirect to user-controlled URL", severity="medium",
      patterns=(r"header\s*\(\s*['\"]Location:\s*['\"]?\s*\.",), message="Open redirect risk.",
      remediation="Allowlist hosts or require relative paths.", cwe="CWE-601", tags=("open-redirect",))
_rule(id="PS044", name="mail() with dynamic headers", severity="medium",
      patterns=(r"\bmail\s*\([^)]*\$",), message="Header injection in mail().",
      remediation="Strip newlines from header fields.", cwe="CWE-93", tags=("header-injection",))

# --- crypto / secrets ------------------------------------------------------ #
_rule(id="PS050", name="md5() used for passwords", severity="medium",
      patterns=(r"\bmd5\s*\([^)]*(pass|pwd)",), message="Fast hash, unsalted unless combined.",
      remediation="Use password_hash() with PASSWORD_DEFAULT.", cwe="CWE-916", tags=("crypto",))
_rule(id="PS051", name="sha1() used for passwords", severity="medium",
      patterns=(r"\bsha1\s*\([^)]*(pass|pwd)",), message="Fast hash for credentials.",
      remediation="Use password_hash() / password_verify().", cwe="CWE-916", tags=("crypto",))
_rule(id="PS052", name="Insecure randomness for tokens", severity="medium",
      patterns=(r"\b(rand|mt_rand|lcg_value|uniqid)\s*\(",), message="Not cryptographically secure.",
      remediation="Use random_bytes() / random_int().", cwe="CWE-338", tags=("crypto",))
_rule(id="PS053", name="Static IV / hardcoded key", severity="medium",
      patterns=(r"(openssl_encrypt|openssl_decrypt)\s*\([^;]*['\"][A-Za-z0-9+/=]{8,}['\"]",),
      message="Hardcoded IV or key literal.", remediation="Store keys outside VCS; generate random IVs.",
      cwe="CWE-321", tags=("crypto", "secrets"))
_rule(id="PS054", name="TLS verification disabled", severity="medium",
      patterns=(r"CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)", r"CURLOPT_SSL_VERIFYHOST\s*,\s*(0|false)"),
      message="Certificate validation turned off.", remediation="Set both options to true.",
      cwe="CWE-295", tags=("crypto",))
_rule(id="PS055", name="Loose comparison in authentication", severity="medium",
      patterns=(r"\b(strcmp|hash_equals)\s*\([^)]*\)\s*(==|!=)", r"\$(pass|pwd|hash|token)\w*\s*==\s*"),
      message="Loose == allows type-juggling bypasses.", remediation="Use === or hash_equals().",
      cwe="CWE-697", tags=("auth", "type-juggling"))

# --- input handling / logic ------------------------------------------------ #
_rule(id="PS060", name="extract() on request data", severity="high",
      patterns=(r"\bextract\s*\(\s*\$_",), message="Overwrites local variables from user input.",
      remediation="Use extract($data, EXTR_SKIP).", cwe="CWE-621", tags=("logic",))
_rule(id="PS061", name="parse_str() into the local scope", severity="medium",
      patterns=(r"\bparse_str\s*\(",), message="parse_str() without a target array pollutes scope.",
      remediation="Always pass the second argument.", cwe="CWE-621", tags=("logic",))
_rule(id="PS062", name="Variable variables", severity="low",
      patterns=(r"\$\$[A-Za-z_]",), message="Dynamic variable names are hard to trace.",
      remediation="Prefer explicit arrays.", cwe="CWE-621", tags=("logic",))
_rule(id="PS063", name="Trust in X-Forwarded-For", severity="low",
      patterns=(r"HTTP_X_FORWARDED_FOR",), message="Client-spoofable unless behind a trusted proxy.",
      remediation="Validate against a known proxy list.", cwe="CWE-348", tags=("logic",))
_rule(id="PS064", name="Trust in Authorization header parsing", severity="low",
      patterns=(r"HTTP_AUTHORIZATION",), message="Verify signature, not just presence.",
      remediation="Use a vetted JWT library.", cwe="CWE-345", tags=("auth",))
_rule(id="PS065", name="in_array() without strict flag", severity="low",
      patterns=(r"\bin_array\s*\([^)]*\)\s*(?!,)", r"array_search\s*\([^)]*\)\s*(?!,)"),
      message="Non-strict search allows type juggling.", remediation="Pass true as the third argument.",
      cwe="CWE-697", tags=("type-juggling",))

# --- uploads / sessions / config ------------------------------------------- #
_rule(id="PS070", name="Upload handling without MIME check", severity="high",
      patterns=(r"\$_FILES\b",), negative=r"mime_content_type|finfo_|getimagesize|exif_imagetype",
      message="$_FILES used without validating the real content type.",
      remediation="Check finfo MIME + extension + store outside the web root.", cwe="CWE-434",
      tags=("upload",))
_rule(id="PS071", name="move_uploaded_file to a user-named path", severity="high",
      patterns=(r"move_uploaded_file\s*\([^,]+,\s*[^)]*\$",), message="Filename may contain traversal or PHP extension.",
      remediation="Regenerate the filename; basename() the original.", cwe="CWE-434", tags=("upload",))
_rule(id="PS072", name="setcookie without HttpOnly/Secure", severity="medium",
      patterns=(r"\bsetcookie\s*\(",), negative=r"HttpOnly", message="Cookie flags may be missing.",
      remediation="Pass ['httponly' => true, 'secure' => true, 'samesite' => 'Strict'].", cwe="CWE-1004",
      tags=("session",))
_rule(id="PS073", name="session_start() without hardening", severity="low",
      patterns=(r"\bsession_start\s*\(\s*\)",), message="Default session cookie params.",
      remediation="Set session.cookie_httponly/secure/samesite before starting.", cwe="CWE-1004",
      tags=("session",))
_rule(id="PS074", name="No CSRF token in a form POST", severity="medium",
      patterns=(r"<form[^>]*method\s*=\s*['\"]post['\"]",), negative=r"csrf|token|_token",
      message="POST form without an apparent CSRF token.", remediation="Add and verify a per-session token.",
      cwe="CWE-352", tags=("csrf",))
_rule(id="PS075", name="World-writable permissions", severity="low",
      patterns=(r"\bchmod\s*\([^,]+,\s*0?777",), message="0777 on files/dirs.",
      remediation="Use 0644/0755 and tighten per need.", cwe="CWE-732", tags=("config",))
_rule(id="PS076", name="display_errors / error_reporting toggled", severity="info",
      patterns=(r"\bini_set\s*\(\s*['\"](display_errors|error_reporting)",),
      message="Debug settings may leak paths in production.", remediation="Gate on an APP_ENV constant.",
      cwe="CWE-209", tags=("config", "info-disclosure"))
_rule(id="PS077", name="phpinfo() left in code", severity="info",
      patterns=(r"\bphpinfo\s*\(",), message="Exposes full environment.", remediation="Remove or restrict.",
      cwe="CWE-200", tags=("info-disclosure",))
_rule(id="PS078", name="Error suppression operator", severity="info",
      patterns=(r"@\$[A-Za-z_]",), message="@ hides failures and can mask security issues.",
      remediation="Handle errors explicitly.", cwe="CWE-390", tags=("quality",))

# --- XXE / SSRF / LDAP ----------------------------------------------------- #
_rule(id="PS080", name="XML parsing without entity hardening", severity="high",
      patterns=(r"simplexml_load_string\s*\(", r"->\s*loadXML\s*\(", r"DOMDocument\b"),
      negative=r"LIBXML_NOENT|libxml_disable_entity_loader|resolveExternals",
      message="External entities may be resolved (XXE / SSRF / file read).",
      remediation="Pass LIBXML_NONET and disable entity loading.", cwe="CWE-611", tags=("xxe", "owasp-a05"))
_rule(id="PS081", name="cURL URL from a variable", severity="medium",
      patterns=(r"CURLOPT_URL\s*,\s*\$",), message="SSRF if the host is user-supplied.",
      remediation="Allowlist schemes and hosts; block link-local ranges.", cwe="CWE-918", tags=("ssrf",))
_rule(id="PS082", name="ldap_search with a variable filter", severity="medium",
      patterns=(r"\bldap_(search|list)\s*\([^)]*\$",), message="LDAP filter injection.",
      remediation="Escape with ldap_escape().", cwe="CWE-90", tags=("ldap",))
_rule(id="PS083", name="preg_* with a variable pattern", severity="low",
      patterns=(r"\bpreg_(match|match_all|replace|split)\s*\(\s*\$",), message="Pattern injection / ReDoS.",
      remediation="Delimit and escape with preg_quote().", cwe="CWE-185", tags=("regex",))

# --- quality / leftovers --------------------------------------------------- #
_rule(id="PS090", name="var_dump / print_r in code", severity="info",
      patterns=(r"\b(var_dump|print_r)\s*\(",), message="Debug output left behind.",
      remediation="Route through a logger.", cwe="CWE-200", tags=("quality",))
_rule(id="PS091", name="TODO/FIXME mentioning security", severity="info",
      patterns=(r"(TODO|FIXME|XXX|HACK)\b[^\n]{0,80}(secur|auth|escap|sanitiz|inject|validat)",),
      message="Unresolved security note.", remediation="Track it in the issue tracker.", cwe="CWE-1059",
      tags=("quality",))
_rule(id="PS092", name="base64_decode() feeding a sink", severity="low",
      patterns=(r"base64_decode\s*\(",), message="Obfuscated payloads hide intent.",
      remediation="Validate the decoded structure before use.", cwe="CWE-477", tags=("obfuscation",))

# --- known secret shapes --------------------------------------------------- #
_rule(id="PS100", name="AWS access key ID", severity="high",
      patterns=(r"\bAKIA[0-9A-Z]{16}\b",), message="Possible AWS access key.",
      remediation="Move to environment variables.", cwe="CWE-798", tags=("secrets",))
_rule(id="PS101", name="GitHub token", severity="high",
      patterns=(r"\bgh[pousr]_[A-Za-z0-9]{20,}",), message="Possible GitHub token.",
      remediation="Revoke and rotate; load from env.", cwe="CWE-798", tags=("secrets",))
_rule(id="PS102", name="Stripe live key", severity="critical",
      patterns=(r"\b(sk|rk)_live_[A-Za-z0-9]{16,}",), message="Stripe live secret key in source.",
      remediation="Rotate and store outside VCS.", cwe="CWE-798", tags=("secrets",))
_rule(id="PS103", name="Slack token", severity="high",
      patterns=(r"\bxox[abprs]-[A-Za-z0-9-]{10,}",), message="Possible Slack token.",
      remediation="Rotate and store outside VCS.", cwe="CWE-798", tags=("secrets",))
_rule(id="PS104", name="Private key block", severity="critical",
      patterns=(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",),
      message="Inline private key.", remediation="Store as a file referenced by path or env.",
      cwe="CWE-321", tags=("secrets",))
_rule(id="PS105", name="JWT literal", severity="low",
      patterns=(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",),
      message="Hardcoded JWT — may embed claims/keys.", remediation="Generate per environment.",
      cwe="CWE-798", tags=("secrets",))

# --- assignment-based credential literals ---------------------------------- #
_rule(id="PS110", name="Hardcoded credential assignment", severity="high",
      patterns=(r"\$[A-Za-z_]*(pass|pwd|secret|token|apikey|api_key|dsn)[A-Za-z_]*\s*=\s*['\"][^'\"]{6,}['\"]",),
      message="Credential literal assigned in code.", remediation="Load from env / secrets manager.",
      cwe="CWE-798", tags=("secrets",))
_rule(id="PS111", name="Credentials in a DSN string", severity="high",
      patterns=(r"['\"](mysql|pgsql|sqlsrv|mongodb)://[^'\":]+:[^'\"@]+@",),
      message="Password embedded in the DSN.", remediation="Compose the DSN from env vars.",
      cwe="CWE-798", tags=("secrets",))


# --------------------------------------------------------------------------- #
# Taint engine configuration
# --------------------------------------------------------------------------- #

def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


SOURCE_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (_c(r"\$_GET\b"), "GET"),
    (_c(r"\$_POST\b"), "POST"),
    (_c(r"\$_REQUEST\b"), "REQUEST"),
    (_c(r"\$_COOKIE\b"), "COOKIE"),
    (_c(r"\$_FILES\b"), "FILES"),
    (_c(r"\$_SERVER\s*\[\s*['\"]HTTP_"), "HTTP header"),
    (_c(r"\bfile_get_contents\s*\(\s*['\"]php://input"), "raw request body"),
    (_c(r"\bgetenv\s*\("), "environment"),
    (_c(r"\bapache_request_headers\s*\("), "request headers"),
    (_c(r"\bfilter_input\s*\("), "filtered input"),
)
SOURCE_RE = re.compile("|".join(f"(?:{p.pattern})" for p, _ in SOURCE_PATTERNS), re.IGNORECASE)

SANITIZER_RE = re.compile(
    r"(?:\(\s*(?:int|integer|float|double|bool|boolean|string|array)\s*\)"
    r"|\b(?:intval|floatval|boolval|strval|abs|round|floor|ceil)\s*\("
    r"|\b(?:htmlspecialchars|htmlentities|strip_tags|urlencode|rawurlencode|http_build_query)\s*\("
    r"|\b(?:escapeshellarg|escapeshellcmd|esc_attr|esc_html)\s*\("
    r"|\b(?:mysqli_real_escape_string|real_escape_string|pg_escape_string|sqlite_escape_string|addslashes|quote)\s*\("
    r"|\b(?:basename|realpath|json_encode|filter_var|preg_quote|ldap_escape|crc32|dechex)\s*\("
    r"|\bPDO\s*::\s*quote\s*\()",
    re.IGNORECASE,
)

TAINT_SINKS: tuple[TaintSink, ...] = (
    TaintSink("T-RCE", "Command execution", "critical",
              _c(r"\b(?:eval|assert|create_function|system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
              "User input reaches a code-execution sink.",
              "Validate against a whitelist; escape with escapeshellarg().", "CWE-78"),
    TaintSink("T-INCLUDE", "File inclusion", "high",
              _c(r"\b(?:include|include_once|require|require_once)\s*\(?"),
              "User input reaches an include path.",
              "Resolve against a fixed base directory; basename() and whitelist.", "CWE-98"),
    TaintSink("T-FILE", "Filesystem operation", "high",
              _c(r"\b(?:file_get_contents|readfile|fopen|file_put_contents|unlink|copy|rename|mkdir|rmdir|file|glob|scandir)\s*\("),
              "User input reaches a filesystem call.",
              "Normalize with realpath() and confine to a base path.", "CWE-22"),
    TaintSink("T-SQL", "SQL query", "critical",
              _c(r"\b(?:mysqli?_query|pg_query|sqlite_query)\s*\(|->\s*(?:query|exec|prepare)\s*\("),
              "User input reaches a SQL statement.",
              "Use prepared statements with bound parameters.", "CWE-89"),
    TaintSink("T-XSS", "HTML output", "medium",
              _c(r"\b(?:echo|print|printf|vprintf|print_r)\b"),
              "User input is written to the response.",
              "Escape with htmlspecialchars($v, ENT_QUOTES, 'UTF-8').", "CWE-79"),
    TaintSink("T-DESER", "Deserialization", "high",
              _c(r"\bunserialize\s*\(|\bjson_decode\s*\("),
              "User input is deserialized.",
              "Restrict allowed classes / validate structure.", "CWE-502"),
    TaintSink("T-HEADER", "Header / cookie", "medium",
              _c(r"\b(?:header|setcookie|setrawcookie)\s*\("),
              "User input reaches a response header.",
              "Strip CR/LF; validate redirect targets.", "CWE-113"),
    TaintSink("T-SSRF", "Remote fetch", "high",
              _c(r"CURLOPT_URL\s*,|\bcurl_init\s*\(|fsockopen\s*\("),
              "User input controls a remote request target.",
              "Allowlist schemes/hosts; block private ranges.", "CWE-918"),
    TaintSink("T-XXE", "XML parsing", "high",
              _c(r"\b(?:simplexml_load_string|simplexml_load_file)\s*\(|->\s*(?:loadXML|load)\s*\("),
              "User input is parsed as XML.",
              "Disable external entities; pass LIBXML_NONET.", "CWE-611"),
    TaintSink("T-LDAP", "LDAP filter", "medium",
              _c(r"\bldap_(?:search|list|read)\s*\("),
              "User input reaches an LDAP filter.", "Escape with ldap_escape().", "CWE-90"),
    TaintSink("T-MAIL", "Mail headers", "medium",
              _c(r"\bmail\s*\("), "User input reaches mail() headers.",
              "Strip newlines from header fields.", "CWE-93"),
    TaintSink("T-EXTRACT", "Variable overwrite", "medium",
              _c(r"\bextract\s*\("), "User input populates the local scope.",
              "Use EXTR_SKIP and namespace your variables.", "CWE-621"),
)

ASSIGN_RE = re.compile(r"\$([A-Za-z_]\w*)\s*(?:\.=|\?\?=|=)\s*([^;]*)$")
FOREACH_RE = re.compile(r"foreach\s*\(([^)]*)\)", re.IGNORECASE)
FUNC_BOUNDARY_RE = re.compile(r"^\s*(?:public|private|protected|static|abstract|final|\s)*function\s+\w+\s*\(", re.IGNORECASE)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


SECRET_ASSIGN_RE = re.compile(
    r"(?P<name>\$?[A-Za-z_][\w]*(?:pass|pwd|secret|token|apikey|api_key|auth|salt|cred|private)[\w]*)"
    r"\s*(?:=|=>|:)\s*(?P<q>['\"])(?P<val>[^'\"\s]{12,200})(?P=q)",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(r"^(?:changeme|your[-_]|xxx+|todo|\{\{|<|\$)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class Scanner:
    def __init__(self, cfg: Config, rules: Sequence[Rule]) -> None:
        self.cfg = cfg
        self.rules = [r for r in rules if self._rule_enabled(r)]
        self.suppress = set(cfg.suppress)

    def _rule_enabled(self, rule: Rule) -> bool:
        if rule.id in self.suppress:
            return False
        if self.cfg.only_tags and not (set(rule.tags) & self.cfg.only_tags):
            return False
        if rule.id == "PS000" or True:
            sev = self._severity(rule.severity)
            return SEVERITY_RANK[sev] >= SEVERITY_RANK[self.cfg.min_severity]

    def _severity(self, severity: str) -> str:
        return self.cfg.severity_map.get(severity, severity)

    def _score(self, severity: str, *, proven: bool = False, path: str = "") -> float:
        base = SEVERITY_WEIGHT.get(severity, 1) * 1.0
        if proven:
            base *= 1.25
        if re.search(r"(test|spec|fixture|example)s?/", path, re.IGNORECASE):
            base *= 0.7
        return round(min(base, 20.0), 2)

    # -- file level -------------------------------------------------------- #
    def scan_file(self, path: Path, root: Path) -> list[Finding]:
        try:
            stat = path.stat()
        except OSError:
            return []
        if stat.st_size > self.cfg.max_file_size:
            return []
        try:
            raw = path.read_bytes()
        except OSError:
            return []
        if b"\x00" in raw[:4096]:
            return []

        text = raw.decode("utf-8", "replace")
        rel = os.path.relpath(path, root) if root else str(path)
        lines = text.splitlines()

        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "*", "#")) and "<?php" not in stripped:
                continue
            for rule in self.rules:
                if rule.negative_re and rule.negative_re.search(line):
                    continue
                for pattern in rule.compiled:
                    m = pattern.search(line)
                    if not m:
                        continue
                    key = (idx, rule.id)
                    if key in seen:
                        continue
                    seen.add(key)
                    sev = self._severity(rule.severity)
                    findings.append(Finding(
                        rule_id=rule.id, name=rule.name, severity=sev, path=rel,
                        line=idx, column=m.start() + 1, code=stripped,
                        message=rule.message, remediation=rule.remediation, cwe=rule.cwe,
                        tags=rule.tags, context=self._context(lines, idx),
                        score=self._score(sev, path=rel),
                    ))
                    break

        findings.extend(self._taint_scan(lines, rel))
        if self.cfg.secrets:
            findings.extend(self._secret_scan(lines, rel))
        return findings

    @staticmethod
    def _context(lines: Sequence[str], idx: int) -> tuple[str, ...]:
        lo, hi = max(1, idx - 2), min(len(lines), idx + 2)
        return tuple(f"{n:>5} | {lines[n - 1]}" for n in range(lo, hi + 1))

    # -- taint tracking ---------------------------------------------------- #
    def _taint_scan(self, lines: Sequence[str], rel: str) -> list[Finding]:
        findings: list[Finding] = []
        tainted: dict[str, str] = {}
        seen: set[tuple[int, str]] = set()

        for idx, line in enumerate(lines, 1):
            if FUNC_BOUNDARY_RE.match(line):
                tainted.clear()

            for fe in FOREACH_RE.finditer(line):
                body = fe.group(1)
                if not SOURCE_RE.search(body):
                    continue
                for var in re.findall(r"\$([A-Za-z_]\w*)", body.split(" as ", 1)[-1]):
                    tainted[var] = "loop over request data"

            for am in ASSIGN_RE.finditer(line):
                var, rhs = am.group(1), am.group(2)
                src = next((label for pat, label in SOURCE_PATTERNS if pat.search(rhs)), None)
                if src:
                    tainted[var] = src
                    continue
                if SANITIZER_RE.search(rhs):
                    tainted.pop(var, None)
                    continue
                derived = next((v for v in tainted if re.search(rf"\${re.escape(v)}\b", rhs)), None)
                if derived:
                    tainted[var] = tainted[derived]
                elif not any(re.search(rf"\${re.escape(v)}\b", rhs) for v in tainted):
                    tainted.pop(var, None)

            if not tainted and not SOURCE_RE.search(line):
                continue

            for sink in TAINT_SINKS:
                m = sink.regex.search(line)
                if not m:
                    continue
                arg = line[m.end():]
                origins: list[str] = []
                for var, origin in tainted.items():
                    if not re.search(rf"\${re.escape(var)}\b", arg):
                        continue
                    if re.search(SANITIZER_RE.pattern + rf"\s*\(\s*\${re.escape(var)}\b", arg, re.IGNORECASE):
                        continue
                    origins.append(f"${var} ({origin})")
                direct = next((label for pat, label in SOURCE_PATTERNS if pat.search(arg)), None)
                if direct and not SANITIZER_RE.search(arg):
                    origins.append(f"superglobal ({direct})")
                if not origins:
                    continue
                key = (idx, sink.rule_id)
                if key in seen:
                    continue
                seen.add(key)
                sev = self._severity(sink.severity)
                findings.append(Finding(
                    rule_id=sink.rule_id, name=sink.name, severity=sev, path=rel,
                    line=idx, column=m.start() + 1, code=line.strip(),
                    message=f"{sink.message} Tainted: {', '.join(dict.fromkeys(origins))}.",
                    remediation=sink.remediation, cwe=sink.cwe, tags=("taint",),
                    context=self._context(lines, idx),
                    score=self._score(sev, proven=True, path=rel),
                ))
        return findings

    # -- entropy secrets --------------------------------------------------- #
    def _secret_scan(self, lines: Sequence[str], rel: str) -> list[Finding]:
        findings: list[Finding] = []
        for idx, line in enumerate(lines, 1):
            for m in SECRET_ASSIGN_RE.finditer(line):
                value = m.group("val")
                if PLACEHOLDER_RE.match(value):
                    continue
                if shannon_entropy(value) < self.cfg.entropy_threshold:
                    continue
                if len(set(value)) < 6:
                    continue
                findings.append(Finding(
                    rule_id="T-SECRET", name="High-entropy secret literal", severity="high",
                    path=rel, line=idx, column=m.start() + 1, code=line.strip(),
                    message=f"'{m.group('name')}' holds a {len(value)}-char literal "
                            f"(entropy {shannon_entropy(value):.2f}).",
                    remediation="Move the value to an environment variable or secret store.",
                    cwe="CWE-798", tags=("secrets", "entropy"),
                    context=self._context(lines, idx), score=self._score("high", path=rel),
                ))
        return findings


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #

def load_rule_pack(path: Path) -> list[Rule]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError:
            raise SystemExit(f"PyYAML required for {path}")
        data = yaml.safe_load(raw) or []
    else:
        data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("rules", [])
    out: list[Rule] = []
    for item in data:
        item.setdefault("patterns", [])
        item["patterns"] = tuple(item["patterns"])
        item.setdefault("tags", ())
        item["tags"] = tuple(item["tags"])
        out.append(Rule(**{k: v for k, v in item.items() if k in Rule.__dataclass_fields__}))
    return out


def load_plugins(paths: Iterable[str]) -> list[Rule]:
    collected: list[Rule] = []
    for p in paths:
        spec = importlib.util.spec_from_file_location(Path(p).stem, p)
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for item in getattr(mod, "RULES", []):
            item.setdefault("patterns", [])
            item["patterns"] = tuple(item["patterns"])
            item.setdefault("tags", ())
            item["tags"] = tuple(item["tags"])
            collected.append(Rule(**{k: v for k, v in item.items() if k in Rule.__dataclass_fields__}))
    return collected


def collect_rules(cfg: Config) -> list[Rule]:
    rules = list(BUILTIN_RULES)
    for d in cfg.rules_dirs:
        root = Path(d)
        if not root.is_dir():
            continue
        for f in sorted(root.iterdir()):
            if f.suffix.lower() in (".json", ".yaml", ".yml"):
                rules.extend(load_rule_pack(f))
    rules.extend(load_plugins(cfg.plugins))
    ids = Counter(r.id for r in rules)
    dupes = {k for k, v in ids.items() if v > 1}
    for r in rules:
        if r.id in dupes:
            r.id = f"{r.id}#{id(r) % 1000:03d}"
            dupes.discard(r.id)
    return rules


# --------------------------------------------------------------------------- #
# File discovery
# --------------------------------------------------------------------------- #

def _matches(rel: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p) for p in patterns)


def git_changed(ref: str, root: Path) -> set[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", ref],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()
    return {line.strip() for line in out.splitlines() if line.strip()}


def iter_files(cfg: Config) -> Iterator[tuple[Path, Path]]:
    changed: set[str] = set()
    if cfg.git_diff:
        changed = git_changed(cfg.git_diff, Path(cfg.targets[0] if cfg.targets else "."))
        if not changed and not cfg.quiet:
            print("phpscan: git diff empty — scanning everything", file=sys.stderr)

    for target in cfg.targets:
        root = Path(target).resolve()
        if root.is_file():
            yield root, root.parent
            continue
        if not root.is_dir():
            print(f"phpscan: no such target: {target}", file=sys.stderr)
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=cfg.follow_symlinks):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                p = Path(dirpath) / name
                rel = os.path.relpath(p, root)
                if p.suffix.lower() not in PHP_EXTS:
                    continue
                if cfg.excludes and _matches(rel, cfg.excludes):
                    continue
                if cfg.includes and not _matches(rel, cfg.includes):
                    continue
                if changed and rel.replace(os.sep, "/") not in changed:
                    continue
                yield p, root


# --------------------------------------------------------------------------- #
# Cache + baseline
# --------------------------------------------------------------------------- #

def file_key(path: Path) -> str:
    try:
        st = path.stat()
    except OSError:
        return ""
    return f"{st.st_mtime_ns}:{st.st_size}"


class Cache:
    def __init__(self, root: Path, enabled: bool) -> None:
        self.path = root / CACHE_NAME
        self.enabled = enabled
        self.data: dict[str, Any] = {}
        if enabled and self.path.is_file():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.data = {}

    def get(self, path: Path) -> list[dict[str, Any]] | None:
        if not self.enabled:
            return None
        entry = self.data.get(str(path))
        if entry and entry.get("key") == file_key(path):
            return entry.get("findings")
        return None

    def put(self, path: Path, findings: list[Finding]) -> None:
        if self.enabled:
            self.data[str(path)] = {"key": file_key(path), "findings": [f.to_dict() for f in findings]}

    def save(self) -> None:
        if self.enabled:
            try:
                self.path.write_text(json.dumps(self.data), encoding="utf-8")
            except OSError:
                pass


def load_baseline(path: str | None) -> set[str]:
    if not path or not Path(path).is_file():
        return set()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    items = data.get("findings", data) if isinstance(data, dict) else data
    return {i["fingerprint"] for i in items if isinstance(i, dict) and "fingerprint" in i}


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line, f.rule_id))


def report_text(findings: list[Finding], cfg: Config, stats: dict[str, Any]) -> str:
    out: list[str] = []
    current = None
    for f in findings:
        if f.path != current:
            current = f.path
            out.append("")
            out.append(colorize(f.path, "path"))
        head = f"  {colorize(f.severity.upper(), f.severity)}  {f.line}:{f.column}  {f.rule_id} {f.name}"
        out.append(head)
        out.extend(f"    {colorize(c, 'dim')}" for c in f.context)
        out.append(f"    {f.message}")
        if f.remediation:
            out.append(f"    {colorize('fix:', 'bold')} {f.remediation}")
        if f.cwe:
            out.append(f"    {colorize(f.cwe, 'dim')}  score {f.score}")
    out.append("")
    out.append(stats_line(findings, stats))
    return "\n".join(out)


def stats_line(findings: list[Finding], stats: dict[str, Any]) -> str:
    by_sev = Counter(f.severity for f in findings)
    parts = [f"{n} {sev}" for sev, n in by_sev.most_common()]
    return (f"{colorize('summary', 'bold')}: {len(findings)} findings "
            f"({', '.join(parts) or 'none'}) across {stats['files']} files "
            f"in {stats['elapsed']:.2f}s")


def report_json(findings: list[Finding], cfg: Config, stats: dict[str, Any]) -> str:
    return json.dumps({
        "tool": {"name": "phpscan", "version": VERSION},
        "stats": stats,
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def report_sarif(findings: list[Finding], cfg: Config, stats: dict[str, Any]) -> str:
    used = {f.rule_id for f in findings}
    rules = []
    for r in BUILTIN_RULES:
        if r.id not in used:
            continue
        rules.append({
            "id": r.id, "name": r.name,
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.message},
            "help": {"text": r.remediation or r.message},
            "defaultConfiguration": {"level": _sarif_level(r.severity)},
            "properties": {"tags": list(r.tags), "cwe": r.cwe},
        })
    results = [{
        "ruleId": f.rule_id,
        "level": _sarif_level(f.severity),
        "message": {"text": f.message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                "region": {"startLine": f.line, "startColumn": max(1, f.column)},
            }
        }],
        "partialFingerprints": {"phpscan/v1": f.fingerprint},
        "properties": {"severity": f.severity, "score": f.score, "cwe": f.cwe},
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "phpscan", "version": VERSION,
                "informationUri": "https://example.invalid/phpscan",
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "note")


def report_markdown(findings: list[Finding], cfg: Config, stats: dict[str, Any]) -> str:
    lines = ["# phpscan report", "", stats_line(findings, stats), "",
             "| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
    for f in findings:
        loc = f"`{f.path}:{f.line}`"
        lines.append(f"| {f.severity} | {f.rule_id} {f.name} | {loc} | {f.message.replace('|', '/')} |")
    return "\n".join(lines)


def report_html(findings: list[Finding], cfg: Config, stats: dict[str, Any]) -> str:
    rows = []
    for f in findings:
        rows.append(
            "<tr class='{sev}'><td>{sev}</td><td>{rid} {name}</td>"
            "<td><code>{path}:{line}</code></td><td>{msg}<br><em>{fix}</em></td></tr>".format(
                sev=f.severity, rid=html.escape(f.rule_id), name=html.escape(f.name),
                path=html.escape(f.path), line=f.line, msg=html.escape(f.message),
                fix=html.escape(f.remediation))
        )
    return f"""<!doctype html><meta charset="utf-8"><title>phpscan report</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;background:#0e1116;color:#e6edf3}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #30363d;padding:.4rem;vertical-align:top}}
.critical{{background:#3d1220}}.high{{background:#3a1a10}}.medium{{background:#3a3310}}.low{{background:#102a33}}
code{{color:#79c0ff}}
</style><h1>phpscan report</h1><p>{html.escape(stats_line(findings, stats))}</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Finding</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>"""


def report_junit(findings: list[Finding], cfg: Config, stats: dict[str, Any]) -> str:
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.path].append(f)
    cases = []
    for path, items in by_file.items():
        inner = "".join(
            f"<testcase classname='{html.escape(path)}' name='{html.escape(i.rule_id)}'>"
            f"<failure type='{i.severity}' message='{html.escape(i.message)}'>"
            f"line {i.line}: {html.escape(i.code)}</failure></testcase>"
            for i in items
        )
        cases.append(f"<testsuite name='{html.escape(path)}' tests='{len(items)}' "
                     f"failures='{len(items)}'>{inner}</testsuite>")
    return (f"<?xml version='1.0' encoding='utf-8'?>"
            f"<testsuites name='phpscan' tests='{len(findings)}' failures='{len(findings)}'>"
            f"{''.join(cases)}</testsuites>")


REPORTERS: dict[str, Callable[[list[Finding], Config, dict[str, Any]], str]] = {
    "text": report_text, "json": report_json, "sarif": report_sarif,
    "markdown": report_markdown, "html": report_html, "junit": report_junit,
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phpscan", description="Advanced PHP static security scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  phpscan src/ --min-severity medium --format sarif -o out.sarif\n"
               "  phpscan . --git-diff origin/main --fail-on high\n"
               "  phpscan src/ --rules-dir ./rules --only-tags sqli,xss\n")
    p.add_argument("targets", nargs="*", help="files or directories to scan")
    p.add_argument("--format", "-f", default="text", choices=sorted(REPORTERS))
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--min-severity", default="low", choices=tuple(SEVERITY_RANK))
    p.add_argument("--fail-on", default="high", choices=tuple(SEVERITY_RANK) + ("none",),
                   help="exit 1 when a finding at/above this level exists")
    p.add_argument("--threads", "-j", type=int, default=max(4, os.cpu_count() or 4))
    p.add_argument("--exclude", "-x", action="append", default=[], metavar="GLOB")
    p.add_argument("--include", action="append", default=[], metavar="GLOB")
    p.add_argument("--only-tags", default="", help="comma-separated tag filter")
    p.add_argument("--suppress", default="", help="comma-separated rule IDs to ignore")
    p.add_argument("--severity-map", default="", help="e.g. medium:high,low:info")
    p.add_argument("--rules-dir", action="append", default=[])
    p.add_argument("--plugin", action="append", default=[], dest="plugins")
    p.add_argument("--config", help="JSON config file")
    p.add_argument("--baseline", help="suppress findings present in this baseline")
    p.add_argument("--write-baseline", metavar="FILE")
    p.add_argument("--cache", action="store_true", help="incremental per-file cache")
    p.add_argument("--git-diff", metavar="REF", help="only scan files changed vs REF")
    p.add_argument("--max-file-size", type=int, default=4 * 1024 * 1024)
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--no-secrets", action="store_true")
    p.add_argument("--entropy", type=float, default=3.5, help="secret entropy floor")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--version", action="version", version=f"phpscan {VERSION}")
    return p


def load_config_file(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    mapping = {
        "exclude": "excludes", "include": "includes", "only_tags": "only_tags",
        "suppress": "suppress", "rules_dir": "rules_dirs", "plugin": "plugins",
    }
    cfg: dict[str, Any] = {}
    for key, value in data.items():
        if key in mapping:
            target = mapping[key]
            if target in ("excludes", "includes", "rules_dirs", "plugins"):
                cfg[target] = value if isinstance(value, list) else [value]
            elif target in ("suppress", "only_tags"):
                cfg[target] = set(value if isinstance(value, list) else [value])
            continue
        cfg[key] = value
    return cfg


def build_config(args: argparse.Namespace) -> Config:
    cfg = Config()
    if args.config:
        for k, v in load_config_file(args.config).items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    if not args.targets:
        for name in CONFIG_NAMES:
            if Path(name).is_file():
                for k, v in load_config_file(name).items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
                break
        args.targets = ["."]

    cfg.targets = args.targets
    cfg.fmt = args.format
    cfg.output = args.output
    cfg.min_severity = args.min_severity
    cfg.fail_on = None if args.fail_on == "none" else args.fail_on
    cfg.threads = max(1, args.threads)
    cfg.max_file_size = args.max_file_size
    cfg.follow_symlinks = args.follow_symlinks
    cfg.excludes = list(dict.fromkeys(cfg.excludes + args.exclude))
    cfg.includes = cfg.includes + args.include
    cfg.rules_dirs = cfg.rules_dirs + args.rules_dir
    cfg.plugins = cfg.plugins + args.plugins
    cfg.suppress |= {s for s in args.suppress.split(",") if s}
    cfg.only_tags |= {t for t in args.only_tags.split(",") if t}
    cfg.secrets = not args.no_secrets
    cfg.entropy_threshold = args.entropy
    cfg.cache = args.cache
    cfg.baseline = args.baseline
    cfg.write_baseline = args.write_baseline
    cfg.git_diff = args.git_diff
    cfg.quiet = args.quiet
    cfg.stats = args.stats
    cfg.list_rules = args.list_rules
    for pair in filter(None, args.severity_map.split(",")):
        if ":" in pair:
            src, dst = pair.split(":", 1)
            cfg.severity_map[src.strip()] = dst.strip()
    return cfg


def main(argv: Sequence[str] | None = None) -> int:
    global USE_COLOR
    args = build_parser().parse_args(argv)
    if args.no_color:
        USE_COLOR = False
    cfg = build_config(args)
    rules = collect_rules(cfg)

    if cfg.list_rules:
        for r in sorted(rules, key=lambda r: r.id):
            print(f"{r.id:<8} {r.severity:<8} {r.name}  [{', '.join(r.tags)}]")
        return 0

    scanner = Scanner(cfg, rules)
    baseline = load_baseline(cfg.baseline)
    root = Path(cfg.targets[0]).resolve()
    cache = Cache(root if root.is_dir() else root.parent, cfg.cache)

    started = time.time()
    findings: list[Finding] = []
    suppressed = 0
    files = 0
    lock_free_results: list[list[Finding]] = []

    targets = list(iter_files(cfg))
    if not cfg.quiet:
        print(f"phpscan {VERSION}: {len(targets)} file(s) queued", file=sys.stderr)

    def work(item: tuple[Path, Path]) -> list[Finding]:
        path, base = item
        cached = cache.get(path)
        if cached is not None:
            return [Finding(**{k: v for k, v in c.items() if k in Finding.__dataclass_fields__})
                    for c in cached]
        result = scanner.scan_file(path, base)
        cache.put(path, result)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.threads) as pool:
        for result in pool.map(work, targets):
            files += 1
            lock_free_results.append(result)

    for result in lock_free_results:
        for f in result:
            if f.fingerprint in baseline:
                suppressed += 1
                continue
            findings.append(f)

    findings = sort_findings(findings)
    elapsed = time.time() - started
    stats = {"files": files, "elapsed": elapsed, "suppressed": suppressed,
             "rules": len(scanner.rules), "by_rule": dict(Counter(f.rule_id for f in findings))}
    cache.save()

    if cfg.write_baseline:
        Path(cfg.write_baseline).write_text(
            json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2), encoding="utf-8")
        if not cfg.quiet:
            print(f"baseline written: {cfg.write_baseline}", file=sys.stderr)

    report = REPORTERS[cfg.fmt](findings, cfg, stats)
    if cfg.output:
        Path(cfg.output).write_text(report, encoding="utf-8")
        if not cfg.quiet:
            print(stats_line(findings, stats), file=sys.stderr)
    else:
        print(report)

    if cfg.stats and cfg.output:
        print(stats_line(findings, stats), file=sys.stderr)
        for rule_id, count in Counter(f.rule_id for f in findings).most_common(10):
            print(f"  {rule_id}: {count}", file=sys.stderr)

    if cfg.fail_on:
        threshold = SEVERITY_RANK[cfg.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
