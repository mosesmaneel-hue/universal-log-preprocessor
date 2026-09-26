import csv
from io import StringIO

from parsers.base import BaseParser


class CSVParser(BaseParser):

    def name(self) -> str:
        return "csv_v1"

    def parse(self, raw_log: str) -> dict:

        raw_log = raw_log.strip()

        # Convert escaped newline characters into real newlines
        raw_log = raw_log.replace("\\n", "\n")

        try:
            reader = csv.DictReader(StringIO(raw_log))
            rows = list(reader)
        except csv.Error as error:
            raise ValueError(f"Invalid CSV format: {error}")

        if not reader.fieldnames:
            raise ValueError("CSV header not found")

        if not rows:
            raise ValueError("CSV contains no data rows")

        return {
            "parser": self.name(),
            "format": "CSV",
            "data": rows
        }