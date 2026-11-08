"""Datensparsame Monatsberichte für Arbeitszeit 30.

Die Aufrufer filtern die Zeilen nach Benutzerrolle und Monat, bevor sie an
diese Funktionen übergeben werden. Keine Dateispeicherung am Server.
"""
from io import BytesIO
from html import escape as html_escape
from xml.sax.saxutils import escape as xml_escape
from zipfile import ZIP_DEFLATED, ZipFile


HEADERS = ("Name", "Beginn (Wien)", "Ende (Wien)",
           "Pause Minuten", "Netto Minuten", "Netto Stunden")


def _spreadsheet_text(value):
    # Excel-intern: inlineStr, niemals Formel-Zellen aus Benutzereingaben.
    value = str(value if value is not None else "")
    return "".join(char for char in value if ord(char) >= 32 or char in "\n\t")


def _col_name(index):
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def make_xlsx(records, month):
    """Minimale standardkonforme XLSX mit allen Angaben als sichere Zellen."""
    sheet = []
    sheet.append('<row r="1"><c r="A1" s="2" t="inlineStr"><is><t>'
                 + xml_escape(f"Arbeitszeit 30 – Monatsbericht {month}")
                 + '</t></is></c></row>')
    sheet.append('<row r="2"></row>')
    headers = []
    for index, name in enumerate(HEADERS, 1):
        cell = f"{_col_name(index)}3"
        headers.append(f'<c r="{cell}" s="1" t="inlineStr"><is><t>'
                       f'{xml_escape(name)}</t></is></c>')
    sheet.append('<row r="3">' + "".join(headers) + '</row>')
    for index, record in enumerate(records, 4):
        if len(record) != len(HEADERS):
            raise ValueError("Bericht hat eine unerwartete Spaltenzahl.")
        cells = []
        for column, value in enumerate(record, 1):
            address = f"{_col_name(column)}{index}"
            if column in (4, 5):
                if not isinstance(value, int) or value < 0:
                    raise ValueError("Minuten müssen nichtnegative ganze Zahlen sein.")
                cells.append(f'<c r="{address}"><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{address}" t="inlineStr"><is><t>'
                             f'{xml_escape(_spreadsheet_text(value))}</t></is></c>')
        sheet.append(f'<row r="{index}">' + "".join(cells) + '</row>')
    last_row = max(3, len(records) + 3)
    xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           '<sheetViews><sheetView workbookViewId="0">'
           '<pane ySplit="3" topLeftCell="A4" activePane="bottomLeft" state="frozen"/>'
           '</sheetView></sheetViews>'
           '<cols><col min="1" max="1" width="26" customWidth="1"/>'
           '<col min="2" max="3" width="22" customWidth="1"/>'
           '<col min="4" max="6" width="17" customWidth="1"/></cols>'
           '<sheetData>' + "".join(sheet) + '</sheetData>'
           f'<autoFilter ref="A3:F{last_row}"/>'
           '</worksheet>')
    styles = ('<?xml version="1.0" encoding="UTF-8"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/>'
              '<name val="Calibri"/></font></fonts>'
              '<fills count="3"><fill><patternFill patternType="none"/></fill>'
              '<fill><patternFill patternType="gray125"/></fill>'
              '<fill><patternFill patternType="solid"><fgColor rgb="FF183752"/>'
              '<bgColor indexed="64"/></patternFill></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
              '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
              '</cellXfs></styleSheet>')
    content_types = ('<?xml version="1.0" encoding="UTF-8"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                     '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                     '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                     '</Types>')
    root_rels = ('<?xml version="1.0" encoding="UTF-8"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
                 ' Target="xl/workbook.xml"/></Relationships>')
    workbook = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
                ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<sheets><sheet name="Monatsbericht" sheetId="1" r:id="rId1"/></sheets></workbook>')
    workbook_rels = ('<?xml version="1.0" encoding="UTF-8"?>'
                     '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                     '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
                     ' Target="worksheets/sheet1.xml"/>'
                     '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"'
                     ' Target="styles.xml"/></Relationships>')
    files = {
        "[Content_Types].xml": content_types,
        "_rels/.rels": root_rels,
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": workbook_rels,
        "xl/styles.xml": styles,
        "xl/worksheets/sheet1.xml": xml,
    }
    result = BytesIO()
    with ZipFile(result, "w", ZIP_DEFLATED) as book:
        for name, content in files.items():
            book.writestr(name, content.encode("utf-8"))
    return result.getvalue()


def make_pdf(records, month):
    """Erstellt eine PDF-Ansicht ohne persistenten Export personenbezogener Daten."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=32, leftMargin=32,
        topMargin=36, bottomMargin=38, title=f"Arbeitszeit {month}")
    styles = getSampleStyleSheet()
    text_style = ParagraphStyle(
        "AZTable", parent=styles["BodyText"], fontSize=8, leading=10)
    title_style = ParagraphStyle(
        "AZTitle", parent=styles["Heading1"], fontSize=16, spaceAfter=9)
    story = [
        Paragraph("Arbeitszeit 30 – Monatsbericht " + html_escape(month), title_style),
        Paragraph("Erfasste Buchungszeiten, keine automatische Lohn- oder Überstundenabrechnung.",
                  styles["Normal"]),
        Spacer(1, 16),
    ]
    cells = [[Paragraph(html_escape(name), text_style) for name in HEADERS]]
    for record in records:
        if len(record) != len(HEADERS):
            raise ValueError("Bericht hat eine unerwartete Spaltenzahl.")
        cells.append([
            Paragraph(html_escape(str(value if value is not None else ""))
                      .replace("\n", " "), text_style)
            for value in record
        ])
    widths = [82, 101, 101, 70, 72, 72]
    table = LongTable(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#183752")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#8999A7")),
        ("LINEBELOW", (0, 1), (-1, -1), 0.2, colors.HexColor("#DFE6ED")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         (colors.white, colors.HexColor("#F3F7FA"))),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5F7284"))
        canvas.drawString(32, 24, f"Arbeitszeit 30 | Monat {month}")
        canvas.drawRightString(A4[0] - 32, 24, f"Seite {doc.page}")

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
