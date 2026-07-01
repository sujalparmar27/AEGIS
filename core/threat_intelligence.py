from rich.panel import Panel
from rich.table import Table
from rich import box

from core.database import Database


class ThreatIntelligence:

    def __init__(self):

        self.db = Database()

    def build(self):

        suspicious = (
            self.db.low_count()
            + self.db.medium_count()
            + self.db.high_count()
        )

        stats = Table.grid(padding=(0, 2))

        stats.add_row(
            "[cyan]Total Scans[/]",
            f"[green]{self.db.total_scans()}[/]"
        )

        stats.add_row(
            "[cyan]Safe URLs[/]",
            f"[green]{self.db.safe_count()}[/]"
        )

        stats.add_row(
            "[cyan]Suspicious URLs[/]",
            f"[yellow]{suspicious}[/]"
        )

        stats.add_row(
            "[cyan]Malicious URLs[/]",
            f"[red]{self.db.critical_count()}[/]"
        )

        stats.add_row(
            "[cyan]Average Risk[/]",
            f"[magenta]{self.db.average_risk()}[/]"
        )

        stats.add_row(
            "[cyan]Highest Risk[/]",
            f"[bold red]{self.db.highest_risk()}[/]"
        )

        panel1 = Panel(
            stats,
            title="[bold cyan]THREAT STATISTICS[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )

        table = Table(
            box=box.ROUNDED,
            expand=True,
        )

        table.add_column("URL")
        table.add_column("Risk", justify="center")

        for url, risk in self.db.dangerous_domains():

            color = "green"

            if risk > 80:
                color = "red"

            elif risk > 40:
                color = "yellow"

            table.add_row(
                url,
                f"[{color}]{risk}[/]"
            )

        panel2 = Panel(
            table,
            title="[bold red]TOP DANGEROUS DOMAINS[/]",
            border_style="red",
            box=box.ROUNDED,
        )

        recent = Table(
            box=box.ROUNDED,
            expand=True,
        )

        recent.add_column("URL")
        recent.add_column("Risk", justify="center")
        recent.add_column("Date")

        for url, risk, date in self.db.recent_threats():

            color = "red" if risk > 80 else "yellow"

            recent.add_row(
                url,
                f"[{color}]{risk}[/]",
                str(date),
            )

        panel3 = Panel(
            recent,
            title="[bold yellow]RECENT HIGH-RISK THREATS[/]",
            border_style="yellow",
            box=box.ROUNDED,
        )

        distribution = Table.grid(padding=(0, 2))

        distribution.add_row(
            "🟢 Safe",
            f"[green]{self.db.safe_count()}[/]"
        )

        distribution.add_row(
            "🟡 Low",
            f"[yellow]{self.db.low_count()}[/]"
        )

        distribution.add_row(
            "🟠 Medium",
            f"[bright_yellow]{self.db.medium_count()}[/]"
        )

        distribution.add_row(
            "🔴 High",
            f"[red]{self.db.high_count()}[/]"
        )

        distribution.add_row(
            "☠ Critical",
            f"[bold red]{self.db.critical_count()}[/]"
        )

        panel4 = Panel(
            distribution,
            title="[bold magenta]RISK DISTRIBUTION[/]",
            border_style="magenta",
        )

        domains = Table(
            box=box.ROUNDED,
            expand=True,
        )

        domains.add_column("Domain")
        domains.add_column("Scans", justify="center")

        for url, count in self.db.most_scanned_domains():

            domains.add_row(
                url,
                str(count),
            )

        panel5 = Panel(
            domains,
            title="[bold green]MOST SCANNED DOMAINS[/]",
            border_style="green",
            box=box.ROUNDED,
        )

        self.db.close()

        return panel1, panel2, panel3, panel4, panel5
