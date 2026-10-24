"""TOML-backed, default-deny policy for MCP tool calls."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast


class PolicyConfigurationError(ValueError):
    """Raised when a policy file cannot be compiled safely."""


class PolicyEffect(StrEnum):
    """The authorization effect assigned to a tool."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """A compiled authorization rule and its argument constraints."""

    tool_name: str
    effect: PolicyEffect
    path_parameters: tuple[str, ...] = ()
    allowed_path_roots: tuple[str, ...] = ()
    sql_parameters: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A redacted authorization result."""

    allowed: bool
    rule_id: str


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Immutable lookup table used on the proxy hot path."""

    default_effect: PolicyEffect
    rules: dict[str, PolicyRule]

    def rule_for(self, tool_name: str) -> PolicyRule | None:
        """Return the optional rule that describes validation constraints."""

        return self.rules.get(tool_name)

    def authorize(self, tool_name: str) -> PolicyDecision:
        """Authorize a discovered tool using a deny-by-default policy."""

        rule = self.rules.get(tool_name)
        if rule is None:
            return PolicyDecision(
                allowed=self.default_effect is PolicyEffect.ALLOW,
                rule_id="policy:default",
            )
        return PolicyDecision(
            allowed=rule.effect is PolicyEffect.ALLOW,
            rule_id=f"policy:{rule.tool_name}",
        )


_TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def load_policy(path: Path) -> CompiledPolicy:
    """Load and validate a policy file before the proxy accepts traffic."""

    if not path.is_file():
        raise PolicyConfigurationError(f"Policy file does not exist: {path}")
    with path.open("rb") as policy_file:
        raw_document = tomllib.load(policy_file)
    document = _table(raw_document, "policy document")
    policy_table = _table(document.get("policy"), "policy")
    default_effect = _effect(policy_table.get("default_effect", "deny"), "policy.default_effect")
    raw_rules = document.get("tool", [])
    if not isinstance(raw_rules, list):
        raise PolicyConfigurationError("'tool' must be an array of TOML tables")

    rules: dict[str, PolicyRule] = {}
    for raw_rule in cast(list[object], raw_rules):
        rule_table = _table(raw_rule, "tool entry")
        tool_name = _tool_name(rule_table.get("name"), "tool.name")
        if tool_name in rules:
            raise PolicyConfigurationError(f"Duplicate policy rule for '{tool_name}'")
        path_parameters = _string_tuple(rule_table.get("path_parameters", []), "path_parameters")
        allowed_path_roots = _path_roots(rule_table.get("allowed_path_roots", []))
        if path_parameters and not allowed_path_roots:
            raise PolicyConfigurationError(
                f"Tool '{tool_name}' declares path parameters without allowed roots"
            )
        rules[tool_name] = PolicyRule(
            tool_name=tool_name,
            effect=_effect(rule_table.get("effect"), f"tool '{tool_name}'.effect"),
            path_parameters=path_parameters,
            allowed_path_roots=allowed_path_roots,
            sql_parameters=_string_tuple(rule_table.get("sql_parameters", []), "sql_parameters"),
        )
    return CompiledPolicy(default_effect=default_effect, rules=rules)


def is_safe_relative_path(value: str, roots: tuple[str, ...]) -> bool:
    """Accept a portable relative path contained by one configured logical root."""

    candidate = value.replace("\\", "/")
    if not candidate or candidate.startswith("/") or ":" in candidate.split("/", 1)[0]:
        return False
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    return any(candidate == root or candidate.startswith(f"{root}/") for root in roots)


def is_read_only_sql(value: str) -> bool:
    """Conservatively accept one SQLite SELECT/WITH statement without mutation tokens."""

    tokens, valid = _lex_sql(value)
    if not valid or not tokens:
        return False
    upper_tokens = tuple(token.upper() for token in tokens)
    if upper_tokens[0] not in {"SELECT", "WITH"}:
        return False
    forbidden = {
        "ALTER", "ANALYZE", "ATTACH", "BEGIN", "COMMIT", "CREATE", "DELETE", "DETACH",
        "DROP", "INSERT", "PRAGMA", "REINDEX", "RELEASE", "REPLACE", "ROLLBACK", "SAVEPOINT",
        "UPDATE", "VACUUM",
    }
    return not any(token in forbidden for token in upper_tokens)


def sqlite_statement_is_single(value: str) -> bool:
    """Reject multiple statements while allowing a single optional trailing semicolon."""

    _, valid = _lex_sql(value)
    return valid


def _table(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyConfigurationError(f"'{name}' must be a TOML table")
    return cast(dict[str, object], value)


def _effect(value: object, name: str) -> PolicyEffect:
    if not isinstance(value, str):
        raise PolicyConfigurationError(f"'{name}' must be 'allow' or 'deny'")
    try:
        return PolicyEffect(value)
    except ValueError as error:
        raise PolicyConfigurationError(f"'{name}' must be 'allow' or 'deny'") from error


def _tool_name(value: object, name: str) -> str:
    if not isinstance(value, str) or _TOOL_NAME_PATTERN.fullmatch(value) is None:
        raise PolicyConfigurationError(f"'{name}' must be a valid MCP tool name")
    return value


def _string_tuple(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigurationError(f"'{name}' must be an array of non-empty strings")
    items = cast(list[object], value)
    if not all(isinstance(item, str) and item for item in items):
        raise PolicyConfigurationError(f"'{name}' must be an array of non-empty strings")
    return tuple(item for item in items if isinstance(item, str))


def _path_roots(value: object) -> tuple[str, ...]:
    roots = _string_tuple(value, "allowed_path_roots")
    if any(not is_safe_relative_path(root, (root,)) for root in roots):
        raise PolicyConfigurationError("allowed_path_roots must be clean relative paths")
    return roots


def _lex_sql(value: str) -> tuple[tuple[str, ...], bool]:
    """Tokenize SQL keywords while safely skipping strings and SQL comments."""

    tokens: list[str] = []
    current: list[str] = []
    index = 0
    semicolon_seen = False
    statement_ended = False
    quote: str | None = None
    bracket_identifier = False
    block_comment = False
    line_comment = False
    while index < len(value):
        char = value[index]
        next_char = value[index + 1] if index + 1 < len(value) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if char == quote:
                if next_char == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if bracket_identifier:
            if char == "]":
                bracket_identifier = False
            index += 1
            continue
        if char == "-" and next_char == "-":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            if statement_ended:
                return (), False
            _flush_sql_token(current, tokens)
            quote = char
            index += 1
            continue
        if char == "[":
            if statement_ended:
                return (), False
            _flush_sql_token(current, tokens)
            bracket_identifier = True
            index += 1
            continue
        if char == ";":
            _flush_sql_token(current, tokens)
            if semicolon_seen:
                return (), False
            semicolon_seen = True
            statement_ended = True
            index += 1
            continue
        if statement_ended:
            if not char.isspace():
                return (), False
            index += 1
            continue
        if char.isalnum() or char == "_":
            current.append(char)
        else:
            _flush_sql_token(current, tokens)
        index += 1
    _flush_sql_token(current, tokens)
    valid = quote is None and not bracket_identifier and not block_comment
    return tuple(tokens), valid


def _flush_sql_token(current: list[str], tokens: list[str]) -> None:
    if current:
        tokens.append("".join(current))
        current.clear()
