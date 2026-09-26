from parsers.json_parser import JSONParser
from parsers.syslog_parser import SyslogParser
from parsers.cef_parser import CEFParser
from parsers.leef_parser import LEEFParser
from parsers.xml_parser import XMLParser
from parsers.csv_parser import CSVParser
from custom.custom_parser import parse_custom_log


class CustomParser:

    def name(self) -> str:
        return "custom_v1"

    def parse(self, raw_log: str) -> dict:
        return parse_custom_log(raw_log)


class ParserRegistry:

    def __init__(self):
        self.parsers = {
            "JSON": JSONParser(),
            "SYSLOG": SyslogParser(),
            "CEF": CEFParser(),
            "LEEF": LEEFParser(),
            "XML": XMLParser(),
            "CSV": CSVParser(),
            "CUSTOM": CustomParser(),
        }

    def get_parser(self, format_name: str):
        parser = self.parsers.get(format_name.upper())

        if parser is None:
            raise ValueError(
                f"No parser registered for format: {format_name}"
            )

        return parser

    def list_parsers(self):
        return [
            {
                "format": format_name,
                "parser": parser.name()
            }
            for format_name, parser in self.parsers.items()
        ]