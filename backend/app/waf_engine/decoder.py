import re
import urllib.parse
import base64
import html
from typing import Dict, List, Tuple

class RecursiveDecoderEngine:
    """
    Layer 2: Recursive Decoder & Obfuscation Analysis Engine.
    Recursively decodes URL encodings, HTML entities, Unicode escapes, and Base64 payloads
    up to a maximum depth of 5 layers to defeat evasion attempts.
    """
    MAX_DEPTH = 5

    BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b")
    UNICODE_ESCAPE_PATTERN = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")
    INLINE_COMMENT_PATTERN = re.compile(r"/\*.*?\*/|--[^\r\n]*", re.DOTALL)

    def decode_payload(self, raw_payload: str) -> Dict:
        """
        Recursively decodes raw payload and computes encoding suspicion score (0-100).
        """
        if not raw_payload:
            return {
                "decoded_payload": "",
                "encoding_depth": 0,
                "encoding_suspicion": 0.0,
                "reasons": []
            }

        current = raw_payload
        depth = 0
        reasons: List[str] = []
        suspicion = 0.0

        # Check initial comment obfuscation density
        comments_found = len(self.INLINE_COMMENT_PATTERN.findall(current))
        if comments_found >= 2:
            suspicion += min(45.0, comments_found * 15.0)
            reasons.append(f"Inline SQL/syntax comment evasion detected ({comments_found} occurrences)")

        # Recursive decoding loop
        for i in range(self.MAX_DEPTH):
            next_str = current

            # 1. URL Decode
            try:
                unquoted = urllib.parse.unquote_plus(next_str)
                if unquoted != next_str:
                    next_str = unquoted
            except Exception:
                pass

            # 2. HTML Entity Decode
            try:
                unescaped = html.unescape(next_str)
                if unescaped != next_str:
                    next_str = unescaped
            except Exception:
                pass

            # 3. Unicode escape decode
            try:
                if "\\u" in next_str or "\\x" in next_str:
                    decoded_unicode = bytes(next_str, 'utf-8').decode('unicode_escape')
                    if decoded_unicode != next_str:
                        next_str = decoded_unicode
            except Exception:
                pass

            # 4. Try Base64 decode for candidate substrings length >= 12
            b64_matches = self.BASE64_PATTERN.findall(next_str)
            for candidate in b64_matches:
                if len(candidate) >= 12:
                    try:
                        decoded_bytes = base64.b64decode(candidate, validate=True)
                        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                        # Only accept if decoded text contains printable ASCII
                        if any(c in decoded_text for c in "<>'\"=();"):
                            next_str = next_str.replace(candidate, decoded_text)
                            reasons.append("Embedded Base64 obfuscated payload decoded")
                            suspicion += 30.0
                    except Exception:
                        continue

            if next_str == current:
                break

            depth += 1
            current = next_str

        # Score calculations based on recursive depth
        if depth == 2:
            suspicion += 35.0
            reasons.append("Double URL/Entity encoding detected (Depth=2)")
        elif depth >= 3:
            suspicion += 70.0
            reasons.append(f"Deep multi-layer recursive obfuscation detected (Depth={depth})")

        # Strip inline comments to reveal hidden keywords
        stripped = self.INLINE_COMMENT_PATTERN.sub(" ", current)
        if stripped != current:
            current = stripped

        return {
            "decoded_payload": current,
            "encoding_depth": depth,
            "encoding_suspicion": min(100.0, suspicion),
            "reasons": reasons
        }
