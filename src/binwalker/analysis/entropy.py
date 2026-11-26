"""Shannon entropy calculations and sliding-window entropy profiling."""

from __future__ import annotations

import math
from collections import Counter

from binwalker.models import EntropyWindow

HIGH_ENTROPY_THRESHOLD = 7.2
PACKED_THRESHOLD = 7.5


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0.0 to 8.0)."""
    total = len(data)
    if total == 0:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def entropy_profile(data: bytes, target_bins: int = 96, min_window: int = 256) -> list[EntropyWindow]:
    """Compute a fixed-resolution sliding/chunked entropy profile for visualization."""
    total = len(data)
    if total == 0:
        return []
    window = max(min_window, math.ceil(total / max(1, target_bins)))
    if total <= min_window:
        return [EntropyWindow(offset=0, size=total, entropy=shannon_entropy(data))]
    windows: list[EntropyWindow] = []
    for offset in range(0, total, window):
        chunk = data[offset : offset + window]
        if chunk:
            windows.append(
                EntropyWindow(offset=offset, size=len(chunk), entropy=shannon_entropy(chunk))
            )
    return windows


def classify_import(symbol: str) -> str:
    """Map an imported API symbol name to a coarse behavioral category."""
    low = symbol.lower().lstrip("_")
    if any(
        k in low
        for k in (
            "virtualalloc",
            "virtualprotect",
            "writeprocessmemory",
            "readprocessmemory",
            "mprotect",
            "mmap",
            "heapalloc",
            "rtlmovememory",
        )
    ):
        return "memory"
    if any(
        k in low
        for k in (
            "createremotethread",
            "createprocess",
            "shellexecute",
            "winexec",
            "execve",
            "system",
            "popen",
            "fork",
            "posix_spawn",
            "openprocess",
            "ntcreatethread",
        )
    ):
        return "process"
    if any(
        k in low
        for k in (
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "wsastartup",
            "internetopen",
            "httpopen",
            "urldownload",
            "curl_",
            "getaddrinfo",
        )
    ):
        return "network"
    if any(
        k in low
        for k in (
            "crypt",
            "bcrypt",
            "aes",
            "sha256",
            "md5",
            "evp_",
            "ssl_",
            "tls_",
            "random",
        )
    ):
        return "crypto"
    if any(
        k in low
        for k in (
            "isdebuggerpresent",
            "checkremotedebugger",
            "ptrace",
            "ntqueryinformationprocess",
            "outputdebugstring",
        )
    ):
        return "anti_debug"
    if any(
        k in low
        for k in (
            "dlopen",
            "dlsym",
            "loadlibrary",
            "getprocaddress",
            "ldrloaddll",
        )
    ):
        return "dynamic"
    if any(
        k in low
        for k in (
            "createfile",
            "writefile",
            "readfile",
            "deletefile",
            "fopen",
            "unlink",
            "chmod",
            "regopen",
            "regset",
        )
    ):
        return "filesystem"
    return "general"
