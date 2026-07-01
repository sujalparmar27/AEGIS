import datetime
import os

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.database import Database


class BulkReport:

    REPORT_DIR = "reports"
    REPORT_FILE = "bulk_report.pdf"

    def __init__(self):

        self.db = Database()
        self.styles = getSampleStyleSheet()

        os.makedirs(self.REPORT_DIR, exist_ok=True)

    def generate(self):

        all_rows = self.db.history()

        seen = set()
        rows = []

        for row in all_rows:

            if row[1] not in seen:

                rows.append(row)
                seen.add(row[1])

        filename = os.path.join(
            self.REPORT_DIR,
            self.REPORT_FILE
        )

        doc = SimpleDocTemplate(filename)

        story = []

        total = len(rows)

        safe = low = medium = high = critical = 0

        total_risk = 0

        highest = None
        lowest = None

        for row in rows:

            risk = row[2]

            total_risk += risk

            if highest is None or risk > highest[2]:
                highest = row

            if lowest is None or risk < lowest[2]:
                lowest = row

            if risk <= 20:
                safe += 1

            elif risk <= 40:
                low += 1

            elif risk <= 60:
                medium += 1

            elif risk <= 80:
                high += 1

            else:
                critical += 1

        average = round(total_risk / total, 2) if total else 0

        story.append(
            Paragraph(
                "<font size='22'><b>AEGIS BULK SECURITY REPORT</b></font>",
                self.styles["Title"],
            )
        )

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                f"<b>Generated :</b> {datetime.datetime.now():%d-%m-%Y %H:%M:%S}",
                self.styles["BodyText"],
            )
        )

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                "<b>EXECUTIVE SUMMARY</b>",
                self.styles["Heading1"],
            )
        )

        story.append(Paragraph(f"Total URLs : {total}", self.styles["BodyText"]))
        story.append(Paragraph(f"Safe : {safe}", self.styles["BodyText"]))
        story.append(Paragraph(f"Low Risk : {low}", self.styles["BodyText"]))
        story.append(Paragraph(f"Medium Risk : {medium}", self.styles["BodyText"]))
        story.append(Paragraph(f"High Risk : {high}", self.styles["BodyText"]))
        story.append(Paragraph(f"Critical : {critical}", self.styles["BodyText"]))

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                "<b>STATISTICS</b>",
                self.styles["Heading1"],
            )
        )

        story.append(
            Paragraph(
                f"Average Risk Score : {average}",
                self.styles["BodyText"],
            )
        )

        if highest:

            story.append(
                Paragraph(
                    f"Highest Risk : {highest[1]} ({highest[2]})",
                    self.styles["BodyText"],
                )
            )

        if lowest:

            story.append(
                Paragraph(
                    f"Lowest Risk : {lowest[1]} ({lowest[2]})",
                    self.styles["BodyText"],
                )
            )

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                "<b>DETAILED RESULTS</b>",
                self.styles["Heading1"],
            )
        )

        table_data = [[
            "URL",
            "Risk",
            "Malicious",
            "Suspicious",
            "Date",
        ]]

        for row in rows:

            url = row[1]

            if len(url) > 45:
                url = url[:42] + "..."

            table_data.append([
                url,
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
            ])

        table = Table(
            table_data,
            colWidths=[300, 45, 55, 65, 90]
        )

        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ])
        )

        for i in range(1, len(table_data)):

            background = (
                colors.whitesmoke
                if i % 2 == 0
                else colors.beige
            )

            table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, i), (-1, i), background),
                ])
            )

        story.append(table)

        story.append(Spacer(1, 20))

        story.append(
            Paragraph(
                "<b>Generated by AEGIS Security Scanner</b>",
                self.styles["Heading2"],
            )
        )

        doc.build(story)

        self.db.close()

        return filename