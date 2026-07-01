from intelligence.urlhaus import URLHaus
from intelligence.openphish import OpenPhish

class ThreatEngine:

    def __init__(self):

        self.urlhaus = URLHaus()
        self.openphish = OpenPhish()

    def analyze(self, url):

        result = {}

        result["urlhaus"] = self.urlhaus.check(url)
        result["openphish"] = self.openphish.check(url)
        return result
