import json

from parsers.base import BaseParser


class JSONParser(BaseParser):

    def name(self) -> str:
        return "json_v1"

    def parse(self, raw_log: str) -> dict:

        data = json.loads(raw_log)

        return {
            "parser": self.name(),
            "format": "JSON",
            "data": data
        }