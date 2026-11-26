"""Printable ASCII and UTF-16LE string extraction with indicator tagging."""

from __future__ import annotations

import re

from binwalker.models import StringMatch

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,256}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,128}")

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKLM\\|HKCU\\|Software\\Microsoft\\Windows)", re.IGNORECASE)
_CMD_RE = re.compile(
    r"(?:/bin/sh|/bin/bash|cmd\.exe|powershell(?:\.exe)?|curl\s|wget\s|chmod\s\+x)", re.IGNORECASE
)
_PATH_RE = re.compile(r"(?:/(?:usr|etc|var|tmp|opt|System|Library)/[^\s'\"]+|C:\\\\?[^\s'\"]+)")


def _categorize(value: str) -> str:
    if _URL_RE.search(value):
        return "url"
    if _REG_RE.search(value):
        return "registry"
    if _CMD_RE.search(value):
        return "command"
    if _IP_RE.search(value):
        return "ip"
    if _PATH_RE.search(value):
        return "path"
    return "general"


def extract_strings(
    data: bytes,
    min_len: int = 5,
    max_results: int = 300,
) -> list[StringMatch]:
    """Extract unique ASCII and UTF-16LE strings prioritized by indicator category."""
    matches: list[StringMatch] = []
    seen: set[str] = set()

    for m in _ASCII_RE.finditer(data):
        text = m.group().decode("ascii", errors="ignore").strip()
        if len(text) < min_len or text in seen:
            continue
        seen.add(text)
        matches.append(
            StringMatch(
                value=text,
                offset=m.start(),
                encoding="ascii",
                category=_categorize(text),
            )
        )
        if len(matches) >= max_results * 3:
            break

    for m in _UTF16_RE.finditer(data):
        text = m.group().decode("utf-16-le", errors="ignore").strip()
        if len(text) < min_len or text in seen:
            continue
        seen.add(text)
        matches.append(
            StringMatch(
                value=text,
                offset=m.start(),
                encoding="utf-16le",
                category=_categorize(text),
            )
        )
        if len(matches) >= max_results * 4:
            break

    priority = {"command": 0, "url": 1, "registry": 2, "ip": 3, "path": 4, "general": 5}
    matches.sort(key=lambda item: (priority.get(item.category, 9), item.offset))
    return matches[:max_results]
