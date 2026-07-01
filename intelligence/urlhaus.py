import requests


class URLHaus:

    API = "https://urlhaus-api.abuse.ch/v1/url/"


    def check(self, url):

        result = {

            "source": "URLHaus",
            "found": False,
            "status": "Unknown",
            "threat": None,
            "tags": []

        }

        try:

            response = requests.post(

                self.API,

                data={"url": url},

                timeout=10

            )

            data = response.json()

            if data.get("query_status") == "ok":

                result["found"] = True
                result["status"] = data.get("url_status")
                result["threat"] = data.get("threat")
                result["tags"] = data.get("tags", [])

            else:

                result["status"] = "Not Listed"

        except Exception as e:

            result["status"] = f"Error: {e}"

        return result