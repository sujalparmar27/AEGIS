import os
from pathlib import Path
from config.config import VIRUSTOTAL_API_KEY

class Settings:

    def __init__(self):

        self.api_key = VIRUSTOTAL_API_KEY
        
    def show(self):

        while True:

            print("\n========== SETTINGS ==========\n")

            print("1. View Configuration")
            print("2. Verify Environment")
            print("3. Verify VirusTotal API")
            print("4. Reset Database")
            print("5. Clear Reports")
            print("0. Back")

            choice = input("\nSelect Option : ")

            if choice == "1":

                self.configuration()

            elif choice == "2":

                self.verify_environment()

            elif choice == "3":

                self.verify_api()

            elif choice == "4":

                self.reset_database()

            elif choice == "5":

                self.clear_reports()

            elif choice == "0":

                break

            else:

                print("Invalid option.")

    def configuration(self):

        print("\n========== CONFIGURATION ==========\n")

        print(f"Platform          : Linux")
        print(f"VirusTotal API    : {'Loaded' if self.api_key else 'Missing'}")
        print(f"Database          : database/aegis.db")
        print(f"Reports Folder    : reports/")
        print(f"Python Version    : {os.sys.version.split()[0]}")

        print()

    def verify_environment(self):

        print("\n========== ENVIRONMENT CHECK ==========\n")

        checks = {
            "Database": Path("database/aegis.db").exists(),
            "Reports Folder": Path("reports").exists(),
            "Config Folder": Path("config").exists(),
            "Assets Folder": Path("assets").exists(),
            "Logs Folder": Path("logs").exists(),
        }

        for name, status in checks.items():

            icon = "✓" if status else "✗"

            print(f"{icon} {name}")

        print()

    def verify_api(self):

        print("\n========== API STATUS ==========\n")

        if self.api_key:

            print("✓ VirusTotal API Key Loaded")

            print(f"Key Length : {len(self.api_key)} characters")

        else:

            print("✗ VirusTotal API Key Missing")

        print()

    def reset_database(self):

        confirm = input(
            "Delete all scan history? (y/n): "
        ).lower()

        if confirm != "y":

            print("Cancelled.\n")

            return

        if Path("database/aegis.db").exists():

            os.remove("database/aegis.db")

            print("✓ Database deleted.")

        else:

            print("Database not found.")

    def clear_reports(self):

        reports = Path("reports")

        count = 0

        if not reports.exists():

            print("Reports folder not found.\n")

            return

        for file in reports.iterdir():

            if file.is_file():

                file.unlink()

                count += 1

        print(f"✓ Deleted {count} report(s).\n")

    