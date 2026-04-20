"""
Heuristic + lightweight ML threat classifier for endpoint events.
Uses feature extraction + scoring without requiring pre-trained models.
"""
import math
import logging

logger = logging.getLogger(__name__)

# High-risk process names
HIGH_RISK_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "pwdump.exe",
    "fgdump.exe", "cachedump.exe", "gsecdump.exe", "meterpreter",
    "msfconsole", "nc.exe", "ncat.exe", "nmap.exe",
}

# Suspicious keywords in command lines
SUSPICIOUS_CMDLINE_KEYWORDS = [
    "sekurlsa", "lsadump", "privilege::debug", "invoke-mimikatz",
    "-encodedcommand", "-enc ", "bypass", "-noprofile", "-windowstyle hidden",
    "powershell -e", "iex(", "invoke-expression", "downloadstring",
    "/dev/tcp/", "nc -e", "bash -i", ">& /dev/tcp",
    "cmd /c echo", "certutil -decode", "bitsadmin /transfer",
    "regsvr32 /s /n /u", "mshta http", "wscript.shell",
]

# Sensitive file paths
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "sam", "ntds.dit", "security\\sam", "lsass",
    "id_rsa", ".ssh/", "authorized_keys",
]


def _cmdline_entropy(cmdline: str) -> float:
    """Shannon entropy of cmdline string."""
    if not cmdline:
        return 0.0
    freq = {}
    for c in cmdline:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    n = len(cmdline)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def classify_event(event: dict) -> dict:
    """
    Returns: {"label": "benign|suspicious|malicious", "score": float, "reasons": list}
    """
    score = 0.0
    reasons = []

    process_name = str(event.get("process_name", "")).lower()
    cmdline = str(event.get("cmdline", "")).lower()
    file_path = str(event.get("file_path", "")).lower()
    username = str(event.get("username", "")).lower()
    dst_port = event.get("network_dst_port")

    # High-risk process
    if any(p in process_name for p in HIGH_RISK_PROCESSES):
        score += 0.8
        reasons.append(f"High-risk process: {process_name}")

    # Suspicious cmdline keywords
    for keyword in SUSPICIOUS_CMDLINE_KEYWORDS:
        if keyword in cmdline:
            score += 0.4
            reasons.append(f"Suspicious cmdline: '{keyword}'")
            break

    # High cmdline entropy (obfuscation indicator)
    entropy = _cmdline_entropy(cmdline)
    if entropy > 4.5 and len(cmdline) > 50:
        score += 0.3
        reasons.append(f"High cmdline entropy: {entropy:.2f} (possible obfuscation)")

    # Sensitive file access
    for path in SENSITIVE_PATHS:
        if path in file_path:
            score += 0.5
            reasons.append(f"Sensitive file access: {path}")
            break

    # Privileged account activity
    if username in ("root", "administrator", "system", "nt authority\\system"):
        score += 0.15
        reasons.append(f"Privileged account: {username}")

    # Dangerous network ports
    if dst_port in (4444, 5555, 1337, 31337, 8888):
        score += 0.6
        reasons.append(f"Suspicious outbound port: {dst_port}")
    elif dst_port in (443, 80, 53):
        # Common but could be C2
        if cmdline and any(k in cmdline for k in ["powershell", "curl", "wget", "python"]):
            score += 0.2
            reasons.append(f"Script process connecting to port {dst_port}")

    score = min(score, 1.0)
    label = "malicious" if score >= 0.7 else ("suspicious" if score >= 0.35 else "benign")

    return {"label": label, "score": round(score, 3), "reasons": reasons}
