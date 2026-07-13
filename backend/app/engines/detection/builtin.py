"""Curated built-in detection rules.

Each rule is production-shaped: precise condition, ATT&CK mapping, documented
false positives, and references. They run on every ingested alert and their
techniques feed MITRE mapping and risk scoring directly.
"""
from __future__ import annotations

from app.engines.detection.rules import (
    DetectionRule,
    FieldMatcher,
    Modifier,
    RuleCondition,
    TechniqueRef,
)
from app.schemas.common import Severity

BUILTIN_RULES: list[DetectionRule] = [
    DetectionRule(
        id="AEG-1001",
        title="Encoded PowerShell command execution",
        description="PowerShell launched with an encoded/obfuscated command — the "
                    "most common malware delivery and post-exploitation pattern.",
        severity=Severity.HIGH,
        condition=RuleCondition(
            all=(FieldMatcher(field="text", values=("powershell",)),),
            any=(
                FieldMatcher(field="text", values=("-enc ", "-enc\t", "-encodedcommand")),
                FieldMatcher(field="text", modifier=Modifier.REGEX,
                             values=(r"frombase64string\s*\(",)),
                FieldMatcher(field="text", values=("-windowstyle hidden", "-noni -nop")),
            ),
        ),
        techniques=(TechniqueRef(
            technique_id="T1059.001",
            name="Command and Scripting Interpreter: PowerShell",
            tactic="execution"),),
        tags=("powershell", "obfuscation"),
        references=("https://attack.mitre.org/techniques/T1059/001/",),
        false_positives=("Admin automation that base64-encodes benign scripts",),
    ),
    DetectionRule(
        id="AEG-1002",
        title="Signed-binary proxy execution (LOLBin)",
        description="rundll32/regsvr32/mshta/certutil used to fetch or execute a "
                    "payload — living-off-the-land defense evasion.",
        severity=Severity.HIGH,
        condition=RuleCondition(
            any=(
                FieldMatcher(field="text", modifier=Modifier.REGEX,
                             values=(r"rundll32(\.exe)?\s+\S+,\s*\w+",)),
                FieldMatcher(field="text", values=("regsvr32 /s /u /i:",
                                                   "regsvr32 /i:http")),
                FieldMatcher(field="text", modifier=Modifier.REGEX,
                             values=(r"mshta(\.exe)?\s+https?:",)),
                FieldMatcher(field="text", values=("certutil -urlcache",
                                                   "certutil.exe -urlcache")),
            ),
        ),
        techniques=(TechniqueRef(
            technique_id="T1218",
            name="System Binary Proxy Execution",
            tactic="defense-evasion"),),
        tags=("lolbin", "defense-evasion"),
        references=("https://lolbas-project.github.io/",),
        false_positives=("Rare legitimate admin use of certutil for cache ops",),
    ),
    DetectionRule(
        id="AEG-1003",
        title="Registry run-key persistence",
        description="Autostart entry written under CurrentVersion\\Run.",
        severity=Severity.MEDIUM,
        condition=RuleCondition(
            all=(FieldMatcher(field="text", values=("currentversion\\run",)),),
        ),
        techniques=(TechniqueRef(
            technique_id="T1547.001",
            name="Registry Run Keys / Startup Folder",
            tactic="persistence"),),
        tags=("persistence", "registry"),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        false_positives=("Software installers legitimately register run keys",),
    ),
    DetectionRule(
        id="AEG-1004",
        title="Credential dumping tooling",
        description="Mimikatz module names or LSASS memory-dump activity.",
        severity=Severity.CRITICAL,
        condition=RuleCondition(
            any=(
                FieldMatcher(field="text", values=("mimikatz", "sekurlsa::",
                                                   "lsadump::")),
                FieldMatcher(field="text", modifier=Modifier.REGEX,
                             values=(r"procdump(\.exe)?\s+(-\w+\s+)*lsass",
                                     r"comsvcs(\.dll)?,\s*minidump")),
            ),
        ),
        techniques=(TechniqueRef(
            technique_id="T1003.001",
            name="OS Credential Dumping: LSASS Memory",
            tactic="credential-access"),),
        tags=("credential-access",),
        references=("https://attack.mitre.org/techniques/T1003/001/",),
        false_positives=("Authorized red-team activity",),
    ),
    DetectionRule(
        id="AEG-1005",
        title="Phishing lure with payment/invoice theme",
        description="Classic financial-pressure lure combined with a link or "
                    "defanged URL in the reported content.",
        severity=Severity.MEDIUM,
        condition=RuleCondition(
            all=(FieldMatcher(field="text", modifier=Modifier.REGEX,
                              values=(r"hxxps?|https?://",)),),
            any=(
                FieldMatcher(field="text", values=(
                    "invoice", "payment required", "payment overdue", "wire transfer",
                    "verify your account", "password expir")),
            ),
        ),
        techniques=(TechniqueRef(
            technique_id="T1566.002",
            name="Phishing: Spearphishing Link",
            tactic="initial-access"),),
        tags=("phishing", "email"),
        references=("https://attack.mitre.org/techniques/T1566/002/",),
        false_positives=("Genuine finance correspondence quoting URLs",),
    ),
    DetectionRule(
        id="AEG-1006",
        title="Ransomware preparation: shadow copy / recovery tampering",
        description="Deletion of volume shadow copies or disabling of recovery — "
                    "near-certain ransomware staging.",
        severity=Severity.CRITICAL,
        condition=RuleCondition(
            any=(
                FieldMatcher(field="text", values=("vssadmin delete shadows",
                                                   "wmic shadowcopy delete")),
                FieldMatcher(field="text", modifier=Modifier.REGEX,
                             values=(r"bcdedit\s+/set.+recoveryenabled\s+no",)),
                FieldMatcher(field="text", values=("wbadmin delete catalog",)),
            ),
        ),
        techniques=(
            TechniqueRef(technique_id="T1490", name="Inhibit System Recovery",
                         tactic="impact"),
            TechniqueRef(technique_id="T1486", name="Data Encrypted for Impact",
                         tactic="impact"),
        ),
        tags=("ransomware", "impact"),
        references=("https://attack.mitre.org/techniques/T1490/",),
        false_positives=("Storage admins pruning shadow copies during maintenance",),
    ),
    DetectionRule(
        id="AEG-1007",
        title="Anomalous sign-in (impossible travel / anonymizer)",
        description="Identity-provider flagged sign-in from impossible travel, "
                    "Tor, or an anonymizing proxy.",
        severity=Severity.HIGH,
        condition=RuleCondition(
            any=(
                FieldMatcher(field="text", values=(
                    "impossible travel", "anonymous ip", "tor exit",
                    "unfamiliar sign-in", "atypical travel")),
            ),
        ),
        techniques=(TechniqueRef(
            technique_id="T1078",
            name="Valid Accounts",
            tactic="initial-access"),),
        tags=("identity", "cloud"),
        references=("https://attack.mitre.org/techniques/T1078/",),
        false_positives=("VPN egress changes; travelling employees",),
    ),
    DetectionRule(
        id="AEG-1008",
        title="Scheduled task persistence",
        description="schtasks used to create a task from alert telemetry.",
        severity=Severity.MEDIUM,
        condition=RuleCondition(
            all=(FieldMatcher(field="text", modifier=Modifier.REGEX,
                              values=(r"schtasks(\.exe)?\s+/create",)),),
            none=(FieldMatcher(field="text", values=("patch-management",)),),
        ),
        techniques=(TechniqueRef(
            technique_id="T1053.005",
            name="Scheduled Task/Job: Scheduled Task",
            tactic="persistence"),),
        tags=("persistence",),
        references=("https://attack.mitre.org/techniques/T1053/005/",),
        false_positives=("Software deployment tooling creating tasks (excluded "
                         "via patch-management tag)",),
    ),
]


def build_detection_engine():
    from app.engines.detection.engine import DetectionEngine

    return DetectionEngine(list(BUILTIN_RULES))
