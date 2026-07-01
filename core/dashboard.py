from datetime import datetime
import itertools
import os
import platform
import subprocess

import psutil

from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from assets.banner import get_banner

from api.virustotal import VirusTotal
from config.config import VIRUSTOTAL_API_KEY

from core.bulk_report import BulkReport
from core.bulk_scanner import BulkScanner
from core.csv_export import CSVExporter
from core.database import Database
from core.help import Help
from core.pdf_report import PDFReport
from core.report_manager import ReportManager
from core.scanner import URLScanner
from core.settings import Settings
from core.threat_intelligence import ThreatIntelligence


class Dashboard:

    def __init__(self, console: Console):

        self.console = console

        self.spinner = itertools.cycle([
            "⠋", "⠙", "⠹", "⠸", "⠼",
            "⠴", "⠦", "⠧", "⠇", "⠏"
        ])

        self.messages = itertools.cycle([
            "Monitoring phishing domains...",
            "Inspecting SSL certificates...",
            "Watching DNS records...",
            "Querying VirusTotal...",
            "Updating IOC database...",
            "Monitoring network traffic...",
            "Checking Threat Intelligence...",
            "Watching suspicious domains..."
        ])

    # -----------------------------------------------------

    def make_panel(self, renderable, title, color="cyan"):

        return Panel(
            renderable,
            title=f"[bold {color}]{title}[/]",
            border_style=color,
            box=box.ROUNDED,
        )

    # -----------------------------------------------------

    def risk_color(self, score):

        if score <= 20:
            return "green"

        if score <= 40:
            return "yellow"

        if score <= 60:
            return "dark_orange"

        if score <= 80:
            return "red"

        return "bold red"

    # -----------------------------------------------------

    def risk_status(self, score):

        if score <= 20:
            return "[green]SAFE[/]"

        if score <= 40:
            return "[yellow]LOW[/]"

        if score <= 60:
            return "[dark_orange]MEDIUM[/]"

        if score <= 80:
            return "[red]HIGH[/]"

        return "[bold red]CRITICAL[/]"
    # -----------------------------------------------------

    def system_overview(self):

        db = Database()

        stats = [
            ("Total Scans", db.total_scans(), "green"),
            ("Safe", db.safe_count(), "green"),
            ("Low Risk", db.low_count(), "yellow"),
            ("Medium Risk", db.medium_count(), "dark_orange"),
            ("High Risk", db.high_count(), "red"),
            ("Critical", db.critical_count(), "bold red"),
        ]

        db.close()

        table = Table.grid(expand=True)
        table.add_column(style="cyan")
        table.add_column(justify="right")

        for title, value, color in stats:
            table.add_row(title, f"[{color}]{value}[/]")

        table.add_row("", "")
        table.add_row("Database", "[green]● Connected[/]")
        table.add_row("VirusTotal", "[green]● Online[/]")
        table.add_row("Scanner", "[green]● Ready[/]")

        return self.make_panel(
            table,
            "SYSTEM OVERVIEW",
            "cyan",
        )

    # -----------------------------------------------------

    def menu(self):

        table = Table.grid(expand=True)

        table.add_column(width=6)
        table.add_column()

        items = [
            ("1", "Scan URL"),
            ("2", "Bulk Scan"),
            ("3", "Scan History"),
            ("4", "Threat Intelligence"),
            ("5", "Reports"),
            ("6", "Settings"),
            ("7", "Help / About"),
            ("0", "Exit"),
        ]

        for key, value in items:

            color = "red" if key == "0" else "green"

            table.add_row(
                f"[bold {color}][{key}][/]",
                value
            )

        return self.make_panel(
            table,
            "MAIN MENU",
            "green",
        )

    # -----------------------------------------------------

    def features(self):

        table = Table.grid()

        features = [
            "URL Reputation",
            "WHOIS Lookup",
            "DNS Intelligence",
            "HTTP Security Headers",
            "SSL Analysis",
            "Technology Detection",
            "Port Scanner",
            "VirusTotal",
            "SQLite Database",
            "Professional PDF Report",
        ]

        for feature in features:
            table.add_row(
                f"[green]✓[/] {feature}"
            )

        return self.make_panel(
            table,
            "FEATURES",
            "magenta",
        )
    # -----------------------------------------------------

    def recent_scans(self):

        db = Database()
        rows = db.recent_scans()
        db.close()

        table = Table(
            expand=True,
            box=box.SIMPLE_HEAVY,
            show_lines=True,
        )

        table.add_column("ID", justify="center", width=5)
        table.add_column("Target")
        table.add_column("Risk", justify="center", width=8)
        table.add_column("Status", justify="center", width=15)

        if not rows:

            table.add_row(
                "-",
                "No scans available",
                "-",
                "-"
            )

        else:

            for row in rows:

                score = row[2]

                table.add_row(
                    str(row[0]),
                    row[1],
                    f"[{self.risk_color(score)}]{score}[/]",
                    self.risk_status(score),
                )

        return self.make_panel(
            table,
            "RECENT SCANS",
            "yellow",
        )

    # -----------------------------------------------------

    def live_monitor(self):

        cpu = psutil.cpu_percent()

        ram = psutil.virtual_memory().percent

        spinner = next(self.spinner)

        message = next(self.messages)

        now = datetime.now().strftime("%H:%M:%S")

        cpu_bar = "█" * int(cpu / 10) + "░" * (10 - int(cpu / 10))
        ram_bar = "█" * int(ram / 10) + "░" * (10 - int(ram / 10))

        table = Table.grid(padding=(0, 1))

        table.add_row("[green]●[/]", "Threat Feed", "[green]ONLINE[/]")
        table.add_row("[green]●[/]", "VirusTotal", "[green]CONNECTED[/]")
        table.add_row("[green]●[/]", "Database", "[green]ACTIVE[/]")
        table.add_row("[green]●[/]", "Scanner", "[green]READY[/]")

        table.add_row("", "", "")

        table.add_row("CPU", cpu_bar, f"{cpu}%")
        table.add_row("RAM", ram_bar, f"{ram}%")

        table.add_row("", "", "")

        table.add_row("Time", now, "")
        table.add_row("Engine", "[green]RUNNING[/]", "")
        table.add_row("Reports", "[green]READY[/]", "")
        table.add_row("Risk Engine", "[green]ACTIVE[/]", "")

        table.add_row("", "", "")

        table.add_row(
            f"[bold yellow]{spinner}[/]",
            f"[cyan]{message}[/]",
            ""
        )

        return self.make_panel(
            table,
            "LIVE SECURITY MONITOR",
            "bright_green",
        )
    # -----------------------------------------------------

    def build(self):

        layout = Layout()

        layout.split_column(
            Layout(name="header", size=11),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=2),
        )

        layout["left"].split_column(
            Layout(name="overview"),
            Layout(name="menu"),
            Layout(name="features"),
        )

        layout["right"].split_column(
            Layout(name="recent", ratio=2),
            Layout(name="monitor", ratio=1),
        )

        layout["header"].update(

            Panel(

                Align.center(get_banner()),

                title="[bold cyan]AEGIS v1.0[/]",

                border_style="bright_green",

                box=box.DOUBLE,

            )

        )

        layout["overview"].update(
            self.system_overview()
        )

        layout["menu"].update(
            self.menu()
        )

        layout["features"].update(
            self.features()
        )

        layout["recent"].update(
            self.recent_scans()
        )

        layout["monitor"].update(
            self.live_monitor()
        )

        layout["footer"].update(

            Panel(

                "[bold bright_green]AEGIS[/bold bright_green] > Select an option",

                border_style="bright_blue",

                box=box.ROUNDED,

            )

        )

        return layout
    # ---------------------------------------------------------
    def show(self):

        actions = {
            "1": self.scan_url,
            "2": self.bulk_scan,
            "3": self.scan_history,
            "4": self.threat_intelligence,
            "5": self.reports,
            "6": self.settings_menu,
            "7": self.help_menu,
        }

        while True:

            self.console.clear()

            self.console.print(
                self.build()
            )

            choice = self.console.input(
                "\n[bold bright_green]AEGIS > [/]"
            ).strip()

            if choice == "0":
                break

            action = actions.get(choice)

            if action:
                action()
            else:
                self.console.print(
                    "[red]Invalid option.[/]"
                )
                input("\nPress Enter...")
    # ---------------------------------------------------------
    def scan_url(self):

        url = self.console.input(
            "\n[bold cyan]Enter URL : [/]"
        ).strip()

        scanner = URLScanner(url)

        result = scanner.scan()

        if not result["status"]:

            self.console.print(
                Panel(
                    "[bold red]Invalid URL[/]",
                    border_style="red",
                )
            )

            input("\nPress Enter...")
            return

        vt = VirusTotal(VIRUSTOTAL_API_KEY)

        vt_result = vt.scan(url)

        db = Database()

        db.save_scan(result, vt_result)

        db.close()

        pdf = PDFReport()

        pdf_file = pdf.generate(result, vt_result)

        self.display_scan_result(
            result,
            vt_result,
            pdf_file,
        )
    # ---------------------------------------------------------
    def display_scan_result(self, result, vt_result, pdf_file):

        whois = result.get("whois") or {}
        ssl = result.get("ssl") or {}
        headers = result.get("headers") or {}
        technology = result.get("technology") or {}
        dns = result.get("dns") or {}
        ports = result.get("ports") or []

        score = result["risk_score"]

        score_text = (
            f"[green]{score}/100[/]"
            if score <= 30 else
            f"[yellow]{score}/100[/]"
            if score <= 70 else
            f"[red]{score}/100[/]"
        )

        left = f"""
        [bold cyan]URL[/]            : {result['url']}
        [bold cyan]Domain[/]         : {result['domain']}
        [bold cyan]IP Address[/]     : {result['ip']}

        [bold green]Registrar[/]     : {whois.get('registrar') or 'Unknown'}
        [bold green]Country[/]       : {whois.get('country') or 'Unknown'}

        [bold yellow]SSL Valid[/]    : {ssl.get('valid', 'Unknown')}
        [bold yellow]SSL Expiry[/]   : {ssl.get('expires', 'Unknown')}

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        [bold magenta]VirusTotal[/]

        Malicious   : {vt_result.get('malicious',0)}
        Suspicious  : {vt_result.get('suspicious',0)}
        Harmless    : {vt_result.get('harmless',0)}
        Undetected  : {vt_result.get('undetected',0)}

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        [bold red]Risk Analysis[/]

        Risk Score     : {score_text}

        Recommendation
        ────────────────────
        💡 {result['recommendation']}
        """
        right = "[bold cyan]HTTP Security[/]\n"
        right += "──────────────────────────\n\n"

        security_headers = headers.get("headers", {})

        if security_headers:

            for header, value in security_headers.items():

                icon = "[green]✓[/]" if value != "Missing" else "[red]✗[/]"

                right += f"{icon} {header}\n"

        else:

            right += "[red]No HTTP security information available.[/]\n"

        right += "\n"

        header_score = headers.get("score", 0)

        header_color = (
            "green"
            if header_score >= 80 else
            "yellow"
            if header_score >= 50 else
            "red"
        )

        right += f"[bold {header_color}]Header Score[/] : {header_score}/100\n"
            # ---------------- DNS ----------------

        if dns:

            right += "\n"
            right += "\n[bold cyan]DNS Intelligence[/]\n"
            right += "──────────────────────────\n"

        if dns.get("A"):
            right += "\nA Records\n"
            for record in dns["A"][:3]:
                right += f" • {record}\n"

        if dns.get("MX"):
            right += "\nMX Records\n"
            for record in dns["MX"]:
                right += f" • {record}\n"

        if dns.get("NS"):
            right += "\nNS Records\n"
            for record in dns["NS"]:
                right += f" • {record}\n"

        if dns.get("TXT"):
            right += f"\nTXT Records : {len(dns['TXT'])}\n"

    # ---------------- Ports ----------------

        if ports:

            right += "\n"
            right += "\n[bold cyan]Open Ports[/]\n"
            right += "──────────────────────────\n"

            for port in ports:

                right += (
                    f"{port['port']:>5}   "
                    f"{port['service']}\n"
                )

    # ---------------- Technology ----------------

        if technology:

            right += "\n"
            right += "\n[bold cyan]Technology Detection[/]\n"
            right += "──────────────────────────\n"

            right += (
                f"\nServer : "
                f"{technology.get('server','Unknown')}\n"
            )

            frameworks = technology.get("framework", [])

            cms = technology.get("cms", [])

            right += (
                "Frameworks : "
                + (
                    ", ".join(frameworks)
                    if frameworks else
                    "None"
                )
                + "\n"
            )

            right += (
                "CMS : "
                + (
                    ", ".join(cms)
                    if cms else
                    "None"
                )
                + "\n"
            )

    # ---------------- Layout ----------------

        grid = Table.grid(expand=True)

        grid.add_column(ratio=6)

        grid.add_column(ratio=5)

        grid.add_row(
            Align.left(left, vertical="top"),
            Align.left(right, vertical="top"),
        )

        self.console.print(

            Panel(
                grid,
                title="[bold green]SCAN RESULT[/]",
                border_style="green",
                box=box.ROUNDED,
            )

        )

        self.console.print(
            "\n[bold green]✓ Scan Completed Successfully[/]"
        )

        choice = self.console.input(
            "\n[bold yellow][O][/]-Open PDF   [bold yellow][C][/]-Continue : "
        ).strip().lower()

        if choice == "o":

            try:

                system = platform.system()

                if system == "Windows":

                    os.startfile(pdf_file)

                elif system == "Linux":

                    subprocess.Popen(["xdg-open", pdf_file])

                elif system == "Darwin":

                    subprocess.Popen(["open", pdf_file])

            except Exception:

                self.console.print(
                    "[red]Unable to open PDF.[/]"
                )

        input("\nPress Enter...")

    def bulk_scan(self):

        filename = self.console.input(
            "\nEnter file path : "
        ).strip()

        try:

            scanner = BulkScanner(VIRUSTOTAL_API_KEY)

            results = scanner.scan_file(filename)

            self.console.print(
                Panel(
                    f"[green]✓ Bulk Scan Complete[/]\n\n"
                    f"Scanned : {len(results)} URLs",
                    border_style="green",
                )
            )

        except Exception as e:

            self.console.print(
                Panel(
                    str(e),
                    border_style="red",
                )
            )

        input("\nPress Enter...")

    def scan_history(self):

        db = Database()

        rows = db.history()

        db.close()

        table = Table(
            title="SCAN HISTORY",
            box=box.ROUNDED,
            show_lines=True,
        )

        table.add_column("ID")
        table.add_column("URL")
        table.add_column("Risk")
        table.add_column("Malicious")
        table.add_column("Suspicious")
        table.add_column("Date")

        for row in rows:

            table.add_row(
                str(row[0]),
                row[1],
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
            )

        self.console.print(table)

        input("\nPress Enter...")

    def threat_intelligence(self):

        ti = ThreatIntelligence()

        stats, dangerous, recent, distribution, domains = ti.build()

        self.console.print(stats)
        self.console.print()
        self.console.print(dangerous)
        self.console.print()
        self.console.print(recent)
        self.console.print()
        self.console.print(distribution)
        self.console.print()
        self.console.print(domains)

        input("\nPress Enter...")
    
    def reports(self):

        manager = ReportManager()

        while True:

            self.console.clear()

            self.console.print(
                manager.menu()
            )

            option = self.console.input(
                "\nSelect option : "
            ).strip()

            if option == "1":

                self.console.clear()

                self.console.print(
                    manager.list_reports()
                )

                input("\nPress Enter...")

            elif option == "2":

                exporter = CSVExporter()

                filename = exporter.export()

                self.console.print(
                    Panel(
                        f"[green]✓ Scan history exported successfully![/]\n\n{filename}",
                        title="CSV EXPORT",
                        border_style="green",
                    )
                )

                input("\nPress Enter...")

            elif option == "3":

                self.console.clear()

                self.console.print(
                    manager.list_reports()
                )

                try:

                    number = int(
                        self.console.input(
                            "\nReport number to delete : "
                        )
                    )

                    if manager.delete_report(number):

                        self.console.print(
                            "\n[green]✓ Report deleted successfully.[/]"
                        )

                    else:

                        self.console.print(
                            "\n[red]Invalid report number.[/]"
                        )

                except ValueError:

                    self.console.print(
                        "\n[red]Please enter a valid number.[/]"
                    )

                input("\nPress Enter...")

            elif option == "4":

                report = BulkReport()

                filename = report.generate()

                self.console.print(
                    Panel(
                        f"[green]✓ Bulk Report Generated[/]\n\n{filename}",
                        title="REPORT",
                        border_style="green",
                    )
                )

                input("\nPress Enter...")

            elif option == "0":

                break

            else:

                self.console.print(
                    "[red]Invalid option.[/]"
                )

                input("\nPress Enter...")
                
    def settings_menu(self):

        Settings().show()

        input("\nPress Enter...")

    def help_menu(self):

        self.console.print(
            Help().show()
        )

        input("\nPress Enter...")

    