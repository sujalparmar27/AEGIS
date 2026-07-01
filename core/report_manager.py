import os

from rich import box
from rich.panel import Panel
from rich.table import Table


class ReportManager:

    REPORT_DIR = "reports"
    PDF_EXTENSION = ".pdf"

    def __init__(self):

        os.makedirs(self.REPORT_DIR, exist_ok=True)

    def _get_reports(self):

        return sorted(
            [
                file
                for file in os.listdir(self.REPORT_DIR)
                if file.endswith(self.PDF_EXTENSION)
            ]
        )

    def list_reports(self):

        files = self._get_reports()

        table = Table(
            box=box.ROUNDED,
            expand=True,
        )

        table.add_column("#", justify="center")
        table.add_column("Report")
        table.add_column("Size")

        if not files:

            table.add_row(
                "-",
                "No reports found",
                "-"
            )

        else:

            for index, file in enumerate(files, start=1):

                path = os.path.join(
                    self.REPORT_DIR,
                    file
                )

                size = os.path.getsize(path)

                table.add_row(
                    str(index),
                    file,
                    f"{size / 1024:.2f} KB"
                )

        return Panel(
            table,
            title="[bold cyan]REPORTS MANAGER[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )

    def delete_report(self, index):

        files = self._get_reports()

        if index < 1 or index > len(files):
            return False

        os.remove(
            os.path.join(
                self.REPORT_DIR,
                files[index - 1]
            )
        )

        return True

    def menu(self):

        table = Table.grid(padding=1)

        table.add_row("[cyan]1[/]", "View PDF Reports")
        table.add_row("[cyan]2[/]", "Export Scan History (CSV)")
        table.add_row("[cyan]3[/]", "Delete Report")
        table.add_row("[cyan]4[/]", "Generate Bulk Report")
        table.add_row("")
        table.add_row("[red]0[/]", "Back")

        return Panel(
            table,
            title="[bold cyan]REPORTS MANAGER[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
