from rich.console import Console

from core.report_manager import ReportManager

console = Console()

manager = ReportManager()

console.print(manager.list_reports())
