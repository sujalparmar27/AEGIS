import socket


class PortScanner:
    """
    Scan a predefined list of common TCP ports.
    """
    COMMON_PORTS = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }

    def __init__(self, timeout=0.5):

        self.timeout = timeout

    def scan(self, host):

        results = []
# Scan common ports
        for port, service in self.COMMON_PORTS.items():
            # Create TCP socket
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

            sock.settimeout(self.timeout)
            
            try:

                result = sock.connect_ex((host, port))

                if result == 0:
                # Port is open
                    results.append({

                        "port": port,

                        "service": service,

                        "state": "OPEN"

                    })

            except socket.error:
                pass

            finally:

                sock.close()

        results.sort(
            key=lambda x: x["port"]
        )

        return results
