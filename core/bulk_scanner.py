import time

from api.virustotal import VirusTotal
from core.database import Database
from core.scanner import URLScanner


class BulkScanner:

    def __init__(self, api_key):

        self.vt = VirusTotal(api_key)
        self.db = Database()

    def _classify_risk(self, score):

        if score <= 20:
            return "SAFE", "safe"

        if score <= 40:
            return "LOW", "low"

        if score <= 60:
            return "MEDIUM", "medium"

        if score <= 80:
            return "HIGH", "high"

        return "CRITICAL", "critical"

    def scan_file(self, filename):

        with open(filename, "r", encoding="utf-8") as file:

            urls = [
                line.strip()
                for line in file
                if line.strip()
            ]

        total = len(urls)

        stats = {
            "safe": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        results = []

        start_time = time.time()

        for index, url in enumerate(urls, start=1):

            scanner = URLScanner(url)
            result = scanner.scan()

            if not result["status"]:

                print(f"[{index}/{total}] ✗ {url}")
                continue

            vt_result = self.vt.scan(url)

            self.db.save_scan(result, vt_result)

            results.append(result)

            score = result["risk_score"]

            label, key = self._classify_risk(score)

            stats[key] += 1

            print(
                f"[{index}/{total}] ✓ {url:<30} [{label}]"
            )

        elapsed = time.time() - start_time

        self.db.close()

        print("\n" + "=" * 50)
        print("            BULK SCAN SUMMARY")
        print("=" * 50)

        print(f"Total URLs      : {total}")
        print(f"Safe            : {stats['safe']}")
        print(f"Low Risk        : {stats['low']}")
        print(f"Medium Risk     : {stats['medium']}")
        print(f"High Risk       : {stats['high']}")
        print(f"Critical        : {stats['critical']}")

        print(f"\nTime Taken      : {elapsed:.2f} sec")

        print("=" * 50)

        return results