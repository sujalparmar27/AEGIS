import requests


class TechnologyDetector:

    HEADERS = {
        "User-Agent": "Mozilla/5.0"
    }

    FRAMEWORKS = {
        "laravel": "Laravel",
        "express": "Express",
        "asp.net": "ASP.NET",
        "django": "Django",
        "flask": "Flask",
        "php": "PHP",
    }

    CMS = {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        'content="wordpress"': "WordPress",
        "joomla": "Joomla",
        "drupal": "Drupal",
        "/cdn/shop/": "Shopify",
        "magento": "Magento",
    }

    # Detect server
    def detect(self, url):
        technologies = {
            "status": "Reachable",
            "server": "Unknown",
            "framework": [],
            "cms": []
        }

        try:
            # Download webpagea
            response = requests.get(
                url,
                headers=self.HEADERS,
                timeout=8,
                allow_redirects=True
            )

            headers = response.headers
            html = response.text.lower()

            technologies["server"] = (
                headers.get("Server")
                or response.url.split("/")[2]
            )

            powered = headers.get(
                "X-Powered-By",
                ""
            ).lower()
            # Detect web frameworks
            for key, value in self.FRAMEWORKS.items():

                if key in powered or key in html:
                    # Remove duplicate detections
                    technologies["framework"].append(value)
            #Detect CMS
            for key, value in self.CMS.items():

                if key in html:

                    technologies["cms"].append(value)

            technologies["framework"] = list(
                dict.fromkeys(technologies["framework"])
            )

            technologies["cms"] = list(
                dict.fromkeys(technologies["cms"])
            )
        
        except requests.RequestException:

            technologies["status"] = "Unreachable"

        return technologies
