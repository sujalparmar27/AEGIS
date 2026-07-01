from rich.panel import Panel


class Help:

    def show(self):

        help_text = """
[bold cyan]AEGIS Security Scanner[/]

Version : 1.0

Platform : Linux

-----------------------------------------

[bold green]Features[/]

• URL Reputation Analysis
• WHOIS Lookup
• DNS Lookup
• SSL Certificate Analysis
• VirusTotal Integration
• Threat Intelligence
• Bulk URL Scanner
• PDF Report Generation
• CSV Export
• Scan History

-----------------------------------------

[bold yellow]Risk Score[/]

0 - 20    Safe

21 - 40   Low Risk

41 - 60   Medium Risk

61 - 80   High Risk

81 - 100  Critical

-----------------------------------------

[bold magenta]Recommendations[/]

• Verify suspicious domains before visiting.

• Keep VirusTotal API active.

• Update threat intelligence regularly.

• Review generated reports.

-----------------------------------------

Developed for Linux
Powered by Python + Rich + SQLite
"""

        return Panel(
            help_text,
            title="[bold green]HELP CENTER[/]",
            border_style="green",
        )
