from rich.console import Console

from core.dashboard import Dashboard


class Aegis:

    def __init__(self):

        self.console = Console()

        self.dashboard = Dashboard(self.console)

    def run(self):

        self.console.clear()

        self.dashboard.show()