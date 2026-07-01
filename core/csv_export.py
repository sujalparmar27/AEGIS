import os
import csv

from core.database import Database


class CSVExporter:

    def __init__(self):

        self.db = Database()

        os.makedirs("reports", exist_ok=True)

    def export(self):

        rows = self.db.history()

        filename = "reports/scan_history.csv"

        with open(filename, "w", newline="", encoding="utf-8") as f:

            writer = csv.writer(f)

            writer.writerow([
                "ID",
                "URL",
                "Risk",
                "Malicious",
                "Suspicious",
                "Scan Date",
            ])

            writer.writerows(rows)

        self.db.close()

        return filename
