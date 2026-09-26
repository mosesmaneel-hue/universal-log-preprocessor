from parsers.base import BaseParser


class CEFParser(BaseParser):

    def name(self) -> str:
        return "cef_v1"

    def parse(self, raw_log: str) -> dict:

        raw_log = raw_log.strip()

        if not raw_log.startswith("CEF:"):
            raise ValueError("Invalid CEF format")

        header, extension = raw_log.split("|", 7)[0:7], ""

        parts = raw_log.split("|", 7)

        if len(parts) < 8:
            raise ValueError("Incomplete CEF format")

        version = parts[0].replace("CEF:", "")
        device_vendor = parts[1]
        device_product = parts[2]
        device_version = parts[3]
        signature_id = parts[4]
        name = parts[5]
        severity = parts[6]
        extension = parts[7]

        fields = {}

        for item in extension.split():
            if "=" in item:
                key, value = item.split("=", 1)
                fields[key] = value

        return {
            "parser": self.name(),
            "format": "CEF",
            "data": {
                "version": version,
                "device_vendor": device_vendor,
                "device_product": device_product,
                "device_version": device_version,
                "signature_id": signature_id,
                "name": name,
                "severity": severity,
                "extension": fields
            }
        }