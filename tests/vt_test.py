from api.virustotal import VirusTotal
from config.config import VIRUSTOTAL_API_KEY

vt = VirusTotal(VIRUSTOTAL_API_KEY)

result = vt.scan("https://google.com")

print(result)