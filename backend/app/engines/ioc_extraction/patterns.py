"""Compiled IOC regular expressions.

These err toward precision over recall (validators in extractor.py reject false
positives such as private IPs or version strings that look like hashes).
"""
from __future__ import annotations

import re

# Order matters where a value could match multiple patterns; the extractor
# resolves overlaps (e.g. an IP inside a URL) by extracting URLs first.

URL = re.compile(
    r"\bhttps?://[^\s\"'<>\)\]]{3,2048}",
    re.IGNORECASE,
)

# Hostname/domain with a valid-looking TLD (2-24 alpha). Excludes trailing dot.
DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)

IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

IPV6 = re.compile(
    r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b",
    re.IGNORECASE,
)

SHA256 = re.compile(r"\b[A-F0-9]{64}\b", re.IGNORECASE)
SHA1 = re.compile(r"\b[A-F0-9]{40}\b", re.IGNORECASE)
MD5 = re.compile(r"\b[A-F0-9]{32}\b", re.IGNORECASE)

EMAIL = re.compile(
    r"\b[A-Z0-9._%+-]+@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,24}\b",
    re.IGNORECASE,
)

# Filenames with common executable/script extensions. Intentionally does not span
# whitespace so it captures the file token, not the surrounding words.
FILENAME = re.compile(
    r"\b[\w\-.]+\.(?:exe|dll|scr|ps1|bat|cmd|vbs|js|jar|hta|lnk|docm|xlsm|"
    r"pdf|zip|rar|7z|iso|img|msi|sys|bin)\b",
    re.IGNORECASE,
)

REGISTRY_KEY = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS)\\[\\\w .\-]{2,512}",
    re.IGNORECASE,
)

# Common mutex naming patterns seen in sandbox reports.
MUTEX = re.compile(
    r"\b(?:Global|Local)\\[A-Za-z0-9_{}\-.]{3,128}",
)

# TLDs that are almost always false positives when seen as bare 'domains'
# (file extensions). The validator drops these.
EXTENSION_TLDS = frozenset(
    {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "py", "txt", "log", "tmp", "dat"}
)
