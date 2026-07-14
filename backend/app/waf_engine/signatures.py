import re
from typing import Dict, List, Tuple

class SignatureEngine:
    """
    Layer 1: Deterministic Signature & Rule Detection Engine.
    Evaluates HTTP request Method, URI, Headers, and Payload against compiled regex patterns
    covering 11 major attack families.
    """
    ATTACK_SIGNATURES: Dict[str, List[Tuple[re.Pattern, float, str]]] = {
        "SQL Injection": [
            (re.compile(r"(?i)\b(UNION(\s+ALL)?\s+SELECT|SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM)\b"), 95.0, "SQL Keywords UNION/SELECT/INSERT/DELETE detected"),
            (re.compile(r"(?i)(\bOR\b|\bAND\b)\s*['\"]?(\d+|=|\w+)['\"]?\s*=\s*['\"]?(\d+|=|\w+)['\"]?"), 90.0, "SQL Tautology OR/AND condition detected"),
            (re.compile(r"(?i)\b(SLEEP|BENCHMARK|PG_SLEEP|WAITFOR\s+DELAY)\s*\("), 95.0, "Time-based Blind SQL Injection function detected"),
            (re.compile(r"(?i)\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|DUAL)\b"), 88.0, "SQL Metadata table enumeration attempt"),
            (re.compile(r"(--|#|/\*|\*/|;--|\s+--\s*)"), 70.0, "SQL Comment or termination delimiter detected"),
        ],
        "XSS": [
            (re.compile(r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>|<\s*script[^>]*>", re.DOTALL), 96.0, "Explicit <script> HTML tag execution attempt"),
            (re.compile(r"(?i)\b(on\w+)\s*=\s*['\"]?[^'\">]+['\"]?"), 89.0, "Inline JavaScript event handler (e.g. onerror/onload)"),
            (re.compile(r"(?i)(javascript|vbscript|data):"), 90.0, "Script execution URI protocol handler"),
            (re.compile(r"(?i)\b(document\.cookie|document\.domain|window\.location|alert\(|confirm\(|prompt\()"), 88.0, "Sensitive DOM interaction JavaScript methods"),
        ],
        "Command Injection": [
            (re.compile(r"(?i)(;\s*(cat|ls|id|whoami|pwd|sh|bash|nc|ncat|netcat|curl|wget|ping)\b|\|\s*(cat|ls|id|whoami|pwd|sh|bash|nc|wget|curl)\b)"), 97.0, "Shell command execution chaining detected"),
            (re.compile(r"(`[^`]+`|\$\([^)]+\))"), 95.0, "Subshell expansion execution syntax"),
            (re.compile(r"(?i)\b(cmd\.exe|powershell(\.exe)?|bin/sh|bin/bash)\b"), 96.0, "System shell interpreter binary reference"),
        ],
        "Path Traversal": [
            (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)"), 94.0, "Directory traversal relative path sequence"),
            (re.compile(r"(?i)(/etc/passwd|/etc/shadow|/proc/self/environ|c:\\windows\\system32|boot\.ini)"), 98.0, "Known operating system sensitive file target"),
        ],
        "File Inclusion": [
            (re.compile(r"(?i)(php://(input|filter|expect)|data://text/plain|file://)"), 95.0, "PHP stream wrapper file inclusion vulnerability attempt"),
            (re.compile(r"(?i)(https?://[^\s]+/.*?\.(txt|php|sh|pl|py)\b)"), 85.0, "Remote File Inclusion (RFI) URL parameter payload"),
        ],
        "XXE": [
            (re.compile(r"(?i)<!DOCTYPE[^>]*!ENTITY[^>]*SYSTEM"), 98.0, "XML External Entity DOCTYPE SYSTEM injection"),
            (re.compile(r"(?i)<!ENTITY\s+%\s+\w+\s+SYSTEM"), 96.0, "Parameter XML External Entity declaration"),
        ],
        "SSTI": [
            (re.compile(r"(\{\{.*?\}\}|\$\{\{.*?\}\}|<%.*?%>)"), 88.0, "Server-Side Template Injection expression execution syntax"),
            (re.compile(r"(?i)(__class__|__mro__|__subclasses__|__builtins__|config\.__class__)"), 97.0, "Python class hierarchy introspection attribute access"),
        ],
        "HTTP Parameter Pollution": [
            (re.compile(r"([&?])([^&=]+)=.*?&\2="), 75.0, "Duplicate HTTP Parameter pollution pattern"),
        ],
        "Encoded Attacks": [
            (re.compile(r"(%[0-9a-fA-F]{2}){4,}"), 70.0, "Dense URL hexadecimal encoding detected"),
            (re.compile(r"(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){3,}"), 82.0, "Dense Unicode or Hex character escape sequences"),
        ],
        "Obfuscated Attacks": [
            (re.compile(r"(?i)\b[A-Z]{2,}/\*\*/[A-Z]{2,}\b"), 94.0, "SQL keyword comment interleaving obfuscation"),
            (re.compile(r"(?i)(String\.fromCharCode|atob\(|btoa\(|eval\()"), 88.0, "JavaScript string de-obfuscation / eval execution call"),
        ]
    }

    def __init__(self):
        self.custom_rules: List[Tuple[re.Pattern, float, str, str]] = []

    def load_custom_rules(self, rules: List[Dict]):
        """Dynamically load active custom rules from DB."""
        self.custom_rules.clear()
        for rule in rules:
            if rule.get('is_active', True):
                try:
                    pat = re.compile(rule['pattern'], re.IGNORECASE)
                    self.custom_rules.append((
                        pat,
                        float(rule.get('severity_score', 80.0)),
                        rule.get('name', 'Custom Rule Triggered'),
                        rule.get('attack_category', 'Custom Signature')
                    ))
                except Exception:
                    continue

    def inspect(self, url: str, headers: Dict[str, str], payload: str) -> Dict:
        """
        Inspect request URL, headers, and payload against all signatures.
        Returns score (0-100), primary attack category, matched rules, and reasons.
        """
        combined_text = f"{url}\n{payload}\n" + "\n".join([f"{k}: {v}" for k, v in headers.items()])
        
        matched_categories: Dict[str, float] = {}
        matched_reasons: List[str] = []
        max_score = 0.0
        primary_category = "Legitimate"

        # Check built-in attack families
        for category, patterns in self.ATTACK_SIGNATURES.items():
            cat_max = 0.0
            for regex, severity, reason in patterns:
                if regex.search(combined_text):
                    cat_max = max(cat_max, severity)
                    matched_reasons.append(f"[{category}] {reason}")
            if cat_max > 0:
                matched_categories[category] = cat_max
                if cat_max > max_score:
                    max_score = cat_max
                    primary_category = category

        # Check custom rules
        for regex, severity, reason, category in self.custom_rules:
            if regex.search(combined_text):
                matched_reasons.append(f"[{category}] {reason}")
                if severity > max_score:
                    max_score = severity
                    primary_category = category

        return {
            "signature_score": min(100.0, max_score),
            "primary_category": primary_category if max_score > 25.0 else "Legitimate",
            "matched_categories": matched_categories,
            "reasons": matched_reasons
        }
