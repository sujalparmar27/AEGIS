import dns.resolver


class DNSLookup:
    """
    Retrieve common DNS records for a domain.
    """
    TXT_PREVIEW_LENGTH = 60
    def lookup(self, domain):

        records = {
            "A": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        }
        # Query common DNS record types
        for record in records:

            try:
# Request DNS records
                answers = dns.resolver.resolve(domain, record)

                for answer in answers:

                    value = str(answer)
# Shorten long TXT records for UI/PDF
                    if record == "TXT":

                        value = value.replace('"', '')

                        if len(value) > self.TXT_PREVIEW_LENGTH:
                            value = value[:self.TXT_PREVIEW_LENGTH] + "..."
                            value = value[:60] + "..."

                    records[record].append(value)

            except Exception:
                pass

        return records