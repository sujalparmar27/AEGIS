import os

from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise RuntimeError(
        "VirusTotal API key not found.\n"
        "Create a .env file and add:\n"
        "VIRUSTOTAL_API_KEY=YOUR_API_KEY"
    )