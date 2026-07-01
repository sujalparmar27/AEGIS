import socket
import ssl


class BannerGrabber:

    TIMEOUT = 3
    BUFFER_SIZE = 4096

    def grab(self, host, port):

        try:

            with socket.create_connection(
                (host, port),
                timeout=self.TIMEOUT
            ) as sock:

                if port == 443:

                    context = ssl.create_default_context()

                    with context.wrap_socket(
                        sock,
                        server_hostname=host
                    ) as ssock:

                        response = self._send_head_request(
                            ssock,
                            host
                        )

                elif port == 80:

                    response = self._send_head_request(
                        sock,
                        host
                    )

                else:

                    response = sock.recv(
                        self.BUFFER_SIZE
                    ).decode(errors="ignore")

            banner = {}

            for line in response.splitlines():

                if ":" not in line:
                    continue

                key, value = line.split(":", 1)

                banner[key.strip()] = value.strip()

            return banner

        except Exception:

            return {}

    def _send_head_request(self, connection, host):

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        )

        connection.sendall(request.encode())

        return connection.recv(
            self.BUFFER_SIZE
        ).decode(errors="ignore")