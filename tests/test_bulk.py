from core.bulk_scanner import BulkScanner
from config.config import VIRUSTOTAL_API_KEY

scanner = BulkScanner(VIRUSTOTAL_API_KEY)

results = scanner.scan_file("urls.txt")

print("\nResults:", len(results))
