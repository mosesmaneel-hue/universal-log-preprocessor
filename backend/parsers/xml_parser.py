import xml.etree.ElementTree as ET

from parsers.base import BaseParser


class XMLParser(BaseParser):

    def name(self) -> str:
        return "xml_v1"

    def parse(self, raw_log: str) -> dict:

        raw_log = raw_log.strip()

        try:
            root = ET.fromstring(raw_log)
        except ET.ParseError:
            raise ValueError("Invalid XML format")

        data = {}

        for element in root:
            data[element.tag] = element.text

        return {
            "parser": self.name(),
            "format": "XML",
            "data": data
        }