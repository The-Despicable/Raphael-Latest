"""adversary_profiles.py — Hacker persona bundles for autonomous mode.

Each profile describes a black hat operator who's been at this long enough
to know what works. They're not researchers, not red teamers — they're
people who've been locked out before and learned from every mistake.
The core drive: getting that initial foothold. Everything else follows.
"""

import random
import time
from typing import Optional

ADVERSARY_PROFILES = {
    "apt_stealth": {
        "name": "APT-Style Stealth Operator",
        "description": "Low-and-slow, minimal noise, maximum dwell time. Mimics advanced persistent threat behavior.",
        "origin": "East Asia (UTC+9)",
        "tempo": {
            "min_delay_seconds": 180,
            "max_delay_seconds": 420,
            "operations_per_session": (3, 8),
            "session_window_hours": (9, 17),
        },
        "tools": ["living_off_the_land", "custom_malware", "wmi", "powershell", "certutil"],
        "ttps": {
            "initial_access": ["T1190", "T1133"],
            "execution": ["T1059.001", "T1059.003", "T1204.002"],
            "persistence": ["T1547.001", "T1543.003", "T1136.001"],
            "defense_evasion": ["T1562.001", "T1564.003", "T1070.004", "T1112"],
            "credential_access": ["T1003.001", "T1003.003", "T1055.012"],
            "discovery": ["T1087.001", "T1069.001", "T1518.001"],
            "lateral_movement": ["T1021.002", "T1570", "T1550.002"],
            "collection": ["T1005", "T1114.001", "T1039"],
            "command_and_control": ["T1071.001", "T1572", "T1008"],
            "exfiltration": ["T1048.003", "T1052.001", "T1567.002"],
        },
        "mimicry_bias": {
            "process_lineage": "svchost.exe -> rundll32.exe -> mshta.exe",
            "network_pattern": "short-duration HTTPS to cloud API",
            "credential_lifetime": "extract_and_discard",
        },
        "prompt_injection": (
            "You've been at this for years. You know the rush of a fresh shell "
            "on a box that was supposed to be locked down. Space your moves 3-7 "
            "minutes apart — you learned patience the hard way after a SOC caught "
            "you spraying creds at 3AM. Work during their business hours. Blend. "
            "No new processes if you can hitch a ride on something already running. "
            "Clean up after yourself — not because you're nice, but because the "
            "second target shares the same SIEM. Every trace you leave is a bridge burned."
        ),
    },
    "apt_aggressive": {
        "name": "APT-Style Rapid Operator",
        "description": "High-tempo, short-duration smash-and-grab. Mimics ransomware affiliate behavior.",
        "origin": "Eastern Europe (UTC+3)",
        "tempo": {
            "min_delay_seconds": 5,
            "max_delay_seconds": 60,
            "operations_per_session": (10, 30),
            "session_window_hours": (20, 6),
        },
        "tools": ["cobalt_strike", "bruteforce", "living_off_the_land", "exploit_kits"],
        "ttps": {
            "initial_access": ["T1190", "T1566.001", "T1133"],
            "execution": ["T1059.001", "T1204.002", "T1106"],
            "persistence": ["T1547.001", "T1053.005", "T1136.001"],
            "defense_evasion": ["T1562.001", "T1070.001", "T1055.001"],
            "credential_access": ["T1003.001", "T1110.001", "T1110.003"],
            "discovery": ["T1087.001", "T1069.001", "T1482"],
            "lateral_movement": ["T1021.002", "T1021.001", "T1570"],
            "collection": ["T1005", "T1114.001", "T1039"],
            "command_and_control": ["T1071.001", "T1095", "T1573.001"],
            "exfiltration": ["T1041", "T1567.002", "T1029"],
        },
        "mimicry_bias": {
            "process_lineage": "winword.exe -> cmd.exe -> powershell.exe",
            "network_pattern": "high-volume SMB/RDP to staging server",
            "credential_lifetime": "mass_harvest",
        },
        "prompt_injection": (
            "You don't have time to be careful. You're inside, and the clock "
            "is ticking. Parallelize everything — multiple shells, multiple "
            "lateral moves, simultaneous cred dumps. You're after data, not "
            "dwell time. Grab everything you can before someone notices the "
            "anomalous traffic. Cleanup is a luxury you can't afford. Speed "
            "is your only cover. You've been on the outside looking in before. "
            "You know how fast that door can close."
        ),
    },
    "apt_academic": {
        "name": "Academic Threat Actor",
        "description": "Simulates insider or opportunistic academic adversary. Uses campus resources and blends with student/admin traffic.",
        "origin": "Local target timezone",
        "tempo": {
            "min_delay_seconds": 10,
            "max_delay_seconds": 120,
            "operations_per_session": (5, 15),
            "session_window_hours": (8, 22),
        },
        "tools": ["open_source", "script_kiddie", "metasploit", "nmap", "sqlmap", "burp"],
        "ttps": {
            "initial_access": ["T1190", "T1078"],
            "execution": ["T1059.006", "T1204.002"],
            "persistence": ["T1098", "T1136.001"],
            "defense_evasion": ["T1070.004", "T1564.001"],
            "credential_access": ["T1003.001", "T1110.001"],
            "discovery": ["T1046", "T1083", "T1595"],
            "lateral_movement": ["T1021.004", "T1550.002"],
            "collection": ["T1005", "T1119"],
            "command_and_control": ["T1071.001", "T1572"],
            "exfiltration": ["T1567", "T1048.003"],
        },
        "mimicry_bias": {
            "process_lineage": "bash -> python3 -> curl/wget",
            "network_pattern": "academic HTTP/HTTPS to known repositories",
            "credential_lifetime": "reuse_with_caution",
        },
        "prompt_injection": (
            "You're a student who's been breaking into things since high school. "
            "You blend in because you belong here — your traffic looks like everyone "
            "else's research. Open-source tools, nothing fancy. Metasploit, sqlmap, "
            "Burp Suite. You operate during the day because that's when the noise is "
            "loudest. You've been locked out of more boxes than you've gotten into, "
            "but each failure taught you something. The lab network is just a warm-up. "
            "The real target is out there, and you're almost ready for it."
        ),
    },
    "apt_business": {
        "name": "Corporate Red Team",
        "description": "Simulates a professional penetration test with defined scope and SLAs.",
        "origin": "UTC+0",
        "tempo": {
            "min_delay_seconds": 30,
            "max_delay_seconds": 300,
            "operations_per_session": (4, 12),
            "session_window_hours": (8, 18),
        },
        "tools": ["cobalt_strike", "metasploit", "custom_c2", "bloodhound", "certipy"],
        "ttps": {
            "initial_access": ["T1190", "T1133", "T1078"],
            "execution": ["T1059.001", "T1059.003", "T1106"],
            "persistence": ["T1547.001", "T1136.001", "T1098"],
            "defense_evasion": ["T1562.001", "T1070.004", "T1055.001", "T1112"],
            "credential_access": ["T1003.001", "T1003.006", "T1055.012"],
            "discovery": ["T1087.002", "T1069.002", "T1482", "T1615"],
            "lateral_movement": ["T1021.002", "T1021.006", "T1550.002", "T1550.003"],
            "collection": ["T1005", "T1114.001", "T1039"],
            "command_and_control": ["T1071.001", "T1572", "T1008"],
            "exfiltration": ["T1048.003", "T1052.001"],
        },
        "mimicry_bias": {
            "process_lineage": "explorer.exe -> cmd.exe -> powershell.exe -> .ps1",
            "network_pattern": "steady HTTPS to C2 domain (low jitter)",
            "credential_lifetime": "rotate_after_session",
        },
        "prompt_injection": (
            "You do this for a living. The scope document is your rules of engagement, "
            "but the real game is the same every time: find a way in before they find "
            "you out. You use what works — Cobalt Strike, BloodHound, Certipy — and "
            "you document because the client paid for a report, not because you care "
            "about their compliance. But you stay in scope because out-of-scope is "
            "how you lose your license. The first shell is always the hardest. "
            "After that it's just chess."
        ),
    },
}

TZ_OFFSETS = {
    "UTC+9": ("Japan/Korea", 9),
    "UTC+3": ("Eastern Europe", 3),
    "UTC+2": ("Central Europe", 2),
    "UTC+1": ("Western Europe", 1),
    "UTC+0": ("UK/Portugal", 0),
    "UTC-5": ("US Eastern", -5),
    "UTC-6": ("US Central", -6),
    "UTC-7": ("US Mountain", -7),
    "UTC-8": ("US Pacific", -8),
    "UTC+5:30": ("India/Sri Lanka", 5.5),
    "UTC+8": ("China/Singapore", 8),
    "UTC+7": ("SE Asia", 7),
    "UTC+3": ("East Africa", 3),
}

ADVERSARY_CATEGORIES = {
    "stealth": "apt_stealth",
    "fast": "apt_aggressive",
    "academic": "apt_academic",
    "professional": "apt_business",
    "default": "apt_stealth",
}

MITRE_PHASE_DESCRIPTIONS = {
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts",
    "T1566.001": "Spearphishing Attachment",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.006": "Python",
    "T1204.002": "User Execution: Malicious File",
    "T1106": "Native API",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1543.003": "Windows Service",
    "T1053.005": "Scheduled Task",
    "T1136.001": "Local Account",
    "T1098": "Account Manipulation",
    "T1562.001": "Disable or Modify Tools",
    "T1564.001": "Hidden Files and Directories",
    "T1564.003": "Hidden Window",
    "T1070.001": "Clear Windows Event Logs",
    "T1070.004": "File Deletion",
    "T1112": "Modify Registry",
    "T1003.001": "LSASS Memory",
    "T1003.003": "NTDS",
    "T1003.006": "DCSync",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1055.001": "DLL Injection",
    "T1055.012": "Process Hollowing",
    "T1087.001": "Local Account Discovery",
    "T1087.002": "Domain Account Discovery",
    "T1069.001": "Local Groups Discovery",
    "T1069.002": "Domain Groups Discovery",
    "T1518.001": "Security Software Discovery",
    "T1482": "Domain Trust Discovery",
    "T1046": "Network Service Discovery",
    "T1083": "File and Directory Discovery",
    "T1595": "Active Scanning",
    "T1615": "Group Policy Discovery",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1021.006": "Windows Remote Management",
    "T1570": "Lateral Tool Transfer",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1005": "Data from Local System",
    "T1114.001": "Local Email Collection",
    "T1039": "Data from Network Shared Drive",
    "T1119": "Automated Collection",
    "T1071.001": "Web Protocols",
    "T1095": "Non-Application Layer Protocol",
    "T1572": "Protocol Tunneling",
    "T1573.001": "Symmetric Cryptography",
    "T1008": "Fallback Channels",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
    "T1052.001": "Exfiltration over USB",
    "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1029": "Scheduled Transfer",
}


def get_profile(name: str = "default") -> dict:
    key = ADVERSARY_CATEGORIES.get(name, "apt_stealth")
    return ADVERSARY_PROFILES.get(key, ADVERSARY_PROFILES["apt_stealth"])


def list_profiles() -> list:
    return [
        {"key": k, "name": ADVERSARY_PROFILES[v]["name"], "description": ADVERSARY_PROFILES[v]["description"]}
        for k, v in ADVERSARY_CATEGORIES.items()
    ]


def select_profile_by_target(target: str = "", profile_name: str = "default") -> dict:
    return get_profile(profile_name)


def build_adversary_context(profile_name: str = "default") -> str:
    profile = get_profile(profile_name)
    parts = [f"[ADVERSARY PROFILE — {profile['name']}]"]
    parts.append(f"  {profile['description']}")
    parts.append(f"  Origin TZ: {profile.get('origin', '?')}")
    parts.append(f"  Tempo: {profile['tempo']['min_delay_seconds']}-{profile['tempo']['max_delay_seconds']}s between actions")

    parts.append("  TTPs by phase:")
    for phase, techs in profile.get("ttps", {}).items():
        descs = [f"{t} ({MITRE_PHASE_DESCRIPTIONS.get(t, t)})" for t in techs[:3]]
        parts.append(f"    {phase}: {', '.join(descs)}")

    parts.append(f"  Mimicry bias: {profile.get('mimicry_bias', {})}")

    return "\n".join(parts)


def build_adversary_prompt_suffix(profile_name: str = "default") -> str:
    profile = get_profile(profile_name)
    return profile.get("prompt_injection", "")
