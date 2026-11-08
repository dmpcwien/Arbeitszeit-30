"""Monatsberichte – Format, Datenisolation und Formel-Sicherheit."""
import io
import unittest
import xml.etree.ElementTree as ET
from zipfile import ZipFile

from reports import make_pdf, make_xlsx


class ReportsTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            ["=SUM(1,1)", "08.11.2026 08:00", "08.11.2026 16:30", 30, 480, "8,00"],
            ["Mitarbeiter & <Test>", "09.11.2026 09:00", "09.11.2026 13:00",
             0, 240, "4,00"],
        ]

    def test_xlsx_is_valid_archive_with_literal_cells_not_formulas(self):
        blob = make_xlsx(self.records, "2026-11")
        with ZipFile(io.BytesIO(blob)) as book:
            names = set(book.namelist())
            self.assertTrue({"[Content_Types].xml", "xl/workbook.xml",
                             "xl/styles.xml", "xl/worksheets/sheet1.xml"} <= names)
            xml = ET.fromstring(book.read("xl/worksheets/sheet1.xml"))
            ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            all_formulas = xml.findall(".//m:f", namespaces=ns)
            self.assertEqual(all_formulas, [])
            a4 = xml.find(".//m:c[@r='A4']", namespaces=ns)
            self.assertEqual(a4.attrib["t"], "inlineStr")
            self.assertEqual(a4.find(".//m:t", namespaces=ns).text, "=SUM(1,1)")
            a5 = xml.find(".//m:c[@r='A5']", namespaces=ns)
            self.assertEqual(a5.find(".//m:t", namespaces=ns).text,
                             "Mitarbeiter & <Test>")
            d4 = xml.find(".//m:c[@r='D4']/m:v", namespaces=ns)
            self.assertEqual(d4.text, "30")

    def test_pdf_has_header_and_valid_signature(self):
        blob = make_pdf(self.records, "2026-11")
        self.assertTrue(blob.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", blob[-256:])
        self.assertGreater(len(blob), 600)

    def test_empty_month_generates_both_formats(self):
        self.assertGreater(len(make_xlsx([], "2026-11")), 300)
        self.assertTrue(make_pdf([], "2026-11").startswith(b"%PDF-"))

    def test_bad_minutes_are_rejected(self):
        bad = [["Mitarbeiter", "8", "9", -1, 30, "0,50"]]
        with self.assertRaises(ValueError):
            make_xlsx(bad, "2026-11")


if __name__ == "__main__":
    unittest.main()
