
from parsers.base import BaseParser


class LEEFParser(BaseParser):

    def name(self) -> str:
        return "leef_v1"

    def parse(self, raw_log: str) -> dict:

        raw_log = raw_log.strip()

        if not raw_log.startswith("LEEF:"):
            raise ValueError("Invalid LEEF format")

        parts = raw_log.split("|", 4)

        if len(parts) < 5:
            raise ValueError("Incomplete LEEF format")

        version = parts[0].replace("LEEF:", "")
        vendor = parts[1]
        product = parts[2]
        version_name = parts[3]
        attributes = parts[4]

        fields = {}

        # LEEF normally uses tab-separated key=value pairs
        for item in attributes.split("\t"):

            item = item.strip()

            if "=" in item:
                key, value = item.split("=", 1)

                key = key.strip()
                value = value.strip()

                fields[key] = value

        return {
            "parser": self.name(),
            "format": "LEEF",
            "data": {
                "version": version,
                "vendor": vendor,
                "product": product,
                "version_name": version_name,
                "attributes": fields
            }
        }
