from rich.text import Text


def get_banner():
    banner = Text()

    banner.append(
r"""
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
""",
        style="bold bright_green",
    )

    banner.append(
        "\n      URL Reputation & Phishing Analyzer\n",
        style="bold cyan",
    )

    banner.append(
        "      Version 1.0  |  Professional Edition",
        style="bold white",
    )

    return banner