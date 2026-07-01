import sqlite3
from pathlib import Path


class Database:

    DB_PATH = "database/aegis.db"

    def __init__(self):

        Path("database").mkdir(exist_ok=True)

        self.conn = sqlite3.connect(self.DB_PATH)
        self.cursor = self.conn.cursor()

        self._create_table()

    def _create_table(self):

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                url TEXT,
                domain TEXT,
                ip TEXT,

                risk INTEGER,

                malicious INTEGER,
                suspicious INTEGER,
                harmless INTEGER,

                ssl_valid TEXT,

                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        self.conn.commit()

    def save_scan(self, result, vt):

        ssl_data = result.get("ssl") or {}

        self.cursor.execute(
            """
            INSERT INTO scans (
                url,
                domain,
                ip,
                risk,
                malicious,
                suspicious,
                harmless,
                ssl_valid
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                result["domain"],
                result["ip"],
                result["risk_score"],
                vt.get("malicious", 0),
                vt.get("suspicious", 0),
                vt.get("harmless", 0),
                str(ssl_data.get("valid", "Unknown")),
            ),
        )

        self.conn.commit()

    def history(self):

        self.cursor.execute(
            """
            SELECT
                id,
                url,
                risk,
                malicious,
                suspicious,
                scan_date
            FROM scans
            ORDER BY id DESC
            """
        )

        return self.cursor.fetchall()

    def recent_scans(self, limit=5):

        self.cursor.execute(
            """
            SELECT
                id,
                url,
                risk
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        return self.cursor.fetchall()

    def total_scans(self):

        self.cursor.execute("SELECT COUNT(*) FROM scans")

        return self.cursor.fetchone()[0]

    def safe_count(self):

        self.cursor.execute(
            "SELECT COUNT(*) FROM scans WHERE risk <= 20"
        )

        return self.cursor.fetchone()[0]

    def low_count(self):

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE risk > 20 AND risk <= 40
            """
        )

        return self.cursor.fetchone()[0]

    def medium_count(self):

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE risk > 40 AND risk <= 60
            """
        )

        return self.cursor.fetchone()[0]

    def high_count(self):

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE risk > 60 AND risk <= 80
            """
        )

        return self.cursor.fetchone()[0]

    def critical_count(self):

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE risk > 80
            """
        )

        return self.cursor.fetchone()[0]

    def average_risk(self):

        self.cursor.execute(
            "SELECT AVG(risk) FROM scans"
        )

        avg = self.cursor.fetchone()[0]

        return round(avg or 0, 2)

    def highest_risk(self):

        self.cursor.execute(
            "SELECT MAX(risk) FROM scans"
        )

        return self.cursor.fetchone()[0] or 0

    def dangerous_domains(self, limit=5):

        self.cursor.execute(
            """
            SELECT
                url,
                risk
            FROM scans
            ORDER BY risk DESC
            LIMIT ?
            """,
            (limit,),
        )

        return self.cursor.fetchall()

    def most_scanned_domains(self, limit=5):

        self.cursor.execute(
            """
            SELECT
                url,
                COUNT(*) AS total
            FROM scans
            GROUP BY url
            ORDER BY total DESC
            LIMIT ?
            """,
            (limit,),
        )

        return self.cursor.fetchall()

    def recent_threats(self, limit=5):

        self.cursor.execute(
            """
            SELECT
                url,
                risk,
                scan_date
            FROM scans
            WHERE risk > 50
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        return self.cursor.fetchall()

    def close(self):

        self.conn.close()