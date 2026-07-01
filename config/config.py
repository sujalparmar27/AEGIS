import os

from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    print("[WARNING] VirusTotal API key not found.")
    print("[WARNING] VirusTotal integration is disabled.")