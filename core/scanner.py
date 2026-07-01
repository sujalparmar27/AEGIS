import socket
import ssl
import datetime
import validators
import whois
import dns.resolver
from core.header_analyzer import HeaderAnalyzer
from urllib.parse import urlparse
from core.technology_detector import TechnologyDetector
from core.dns_lookup import DNSLookup
from core.port_scanner import PortScanner

class URLScanner:

    def __init__(self, url: str):

        self.url = url.strip()
        self.technology = {}
        self.dns = {}
        
        if not self.url.startswith(("http://", "https://")):
            self.url = "https://" + self.url

        self.domain = urlparse(self.url).netloc

    def validate(self):

            return validators.url(self.url)

    def resolve_ip(self):

        try:
            return socket.gethostbyname(self.domain)

        except Exception:
            return None

    def whois_lookup(self):

        try:

            data = whois.whois(self.domain)

            return {
                "registrar": data.registrar,
                "creation_date": str(data.creation_date),
                "expiration_date": str(data.expiration_date),
                "country": data.country,
            }

        except Exception:

            return None

    def ssl_check(self):

        try:

            context = ssl.create_default_context()

            with context.wrap_socket(
                socket.socket(),
                server_hostname=self.domain,
            ) as s:

                s.settimeout(5)

                s.connect(
                    (self.domain, 443)
                )

                cert = s.getpeercert()

                expiry = datetime.datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z",
                )

                return {
                    "issuer": cert["issuer"],
                    "expires": expiry.strftime("%Y-%m-%d"),
                    "valid": expiry > datetime.datetime.utcnow(),
                }

        except Exception:

            return None
    
    def threat_level(self, score):

        if score <= 20:
            return (
                "🟢 SAFE",
                "No immediate threat detected."
            )

        elif score <= 40:
            return (
                "🟡 LOW RISK",
                "Proceed with normal caution."
            )

        elif score <= 60:
            return (
                "🟠 MEDIUM RISK",
                "Some suspicious indicators found."
            )

        elif score <= 80:
            return (
                "🔴 HIGH RISK",
                "Potential phishing or malicious website."
            )

        else:
            return (
                "☠️ CRITICAL",
                "Strong indicators of malicious activity."
            )

    def calculate_risk(self):

        score = 0

        suspicious_tlds = [
            ".xyz",
            ".top",
            ".click",
            ".gq",
            ".ml",
            ".cf",
            ".tk",
            ".buzz",
            ".zip",
            ".review",
        ]

        for tld in suspicious_tlds:

            if self.domain.endswith(tld):
                score += 35
                break

        if "-" in self.domain:
            score += 10

        if len(self.domain) > 30:
            score += 10

        if self.domain.count(".") >= 3:
            score += 15

        if len(self.url) > 75:
            score += 10

        if not self.url.startswith("https://"):
            score += 10

        ssl_info = self.ssl_check()

        if ssl_info is None:
            score += 20

        elif not ssl_info["valid"]:
            score += 20

        whois_data = self.whois_lookup()

        if whois_data is None:

            score += 15

        else:

            creation = whois_data.get("creation_date")

            if creation:

                creation = str(creation)

                if "2025" in creation or "2026" in creation:
                    score += 20

                elif "2024" in creation:
                    score += 10
    
            dns_records = DNSLookup().lookup(self.domain)

            if len(dns_records["MX"]) == 0:
                score += 5

            if self.resolve_ip() is None:
                score += 25

        return min(score, 100)

    def scan(self):

        if not self.validate():

            return {
                "status": False,
                "message": "Invalid URL",
            }

        ip = self.resolve_ip()
        
        ports = []

        if ip:
            ports = PortScanner().scan(ip)

        whois_data = self.whois_lookup()

        ssl_data = self.ssl_check()

        header_analysis = HeaderAnalyzer().analyze(self.url)

        tech = TechnologyDetector()
        self.technology = tech.detect(self.url)

        dns = DNSLookup()
        self.dns = dns.lookup(self.domain)

        score = self.calculate_risk()

        header_score = header_analysis.get("score", 0)

        if header_score < 40:
            score += 15

        elif header_score < 70:
            score += 8

        score = min(score, 100)

        threat, recommendation = self.threat_level(score)

        return {

            "status": True,

            "url": self.url,

            "domain": self.domain,

            "ip": ip,

            "whois": whois_data,

            "ssl": ssl_data,

            "headers": header_analysis,

            "technology": self.technology,

            "ports": ports,

            "dns": self.dns,

            "risk_score": score,

            "threat_level": threat,

            "recommendation": recommendation,

            }
    