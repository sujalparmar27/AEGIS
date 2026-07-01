import requests


class OpenPhish:

    FEED = "https://openphish.com/feed.txt"


    def check(self, url):

        result = {

            "source": "OpenPhish",
            "found": False,
            "status": "Not Listed"

        }

        try:

            response = requests.get(

                self.FEED,

                timeout=10

            )

            if response.status_code == 200:

                urls = response.text.splitlines()

                if url in urls:

                    result["found"] = True
                    result["status"] = "Phishing"

        except Exception as e:

            result["status"] = f"Error: {e}"

        return result
