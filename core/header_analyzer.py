import requests


class HeaderAnalyzer:

    SECURITY_HEADERS = {
        "Strict-Transport-Security": (
            "HSTS",
            15,
            "Missing HSTS header."
        ),
        "Content-Security-Policy": (
            "CSP",
            20,
            "Missing Content Security Policy."
        ),
        "X-Frame-Options": (
            "Clickjacking Protection",
            15,
            "Missing X-Frame-Options."
        ),
        "X-Content-Type-Options": (
            "MIME Protection",
            10,
            "Missing X-Content-Type-Options."
        ),
        "Referrer-Policy": (
            "Referrer Policy",
            10,
            "Missing Referrer-Policy."
        ),
        "Permissions-Policy": (
            "Permissions Policy",
            10,
            "Missing Permissions-Policy."
        ),
        "Cross-Origin-Opener-Policy": (
            "COOP",
            10,
            "Missing Cross-Origin-Opener-Policy."
        ),
        "Cross-Origin-Embedder-Policy": (
            "COEP",
            10,
            "Missing Cross-Origin-Embedder-Policy."
        ),
    }

    def analyze(self, url):

        result = {
            "headers": {},
            "score": 0,
            "missing": [],
            "recommendations": []
        }

        try:

            # Download webpage
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={
                    "User-Agent": "AEGIS Security Scanner"
                },
            )

            headers = response.headers
            score = 0

            # Check required security headers
            for header, (_, points, recommendation) in self.SECURITY_HEADERS.items():

                if header in headers:

                    result["headers"][header] = headers[header]
                    score += points

                else:

                    result["headers"][header] = "Missing"
                    result["missing"].append(header)
                    result["recommendations"].append(recommendation)

            result["score"] = min(score, 100)

        except requests.RequestException as e:

            result["error"] = str(e)

        return result