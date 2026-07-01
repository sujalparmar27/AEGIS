import requests
import time


class VirusTotal:

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def scan(self, url):

        headers = {
            "x-apikey": self.api_key
        }

        try:

            response = requests.post(
                f"{self.base_url}/urls",
                headers=headers,
                data={"url": url},
                timeout=30
            )

            if response.status_code != 200:
                return {
                    "status": False,
                    "error": response.text
                }

            analysis_id = response.json()["data"]["id"]

            time.sleep(3)

            response = requests.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=headers,
                timeout=30
            )

            if response.status_code != 200:
                return {
                    "status": False,
                    "error": response.text
                }

            stats = response.json()["data"]["attributes"]["stats"]

            return {
                "status": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        except Exception as e:
            return {
                "status": False,
                "error": str(e)
            }