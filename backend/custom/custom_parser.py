import re


def parse_custom_log(raw_log: str) -> dict:
    fields = {}

    pattern = r'(\w+)=("[^"]*"|\S+)'

    matches = re.findall(pattern, raw_log)

    for key, value in matches:
        fields[key] = value.strip('"')

    return {
        "parser": "custom_v1",
        "format": "CUSTOM",
        "raw_log": raw_log,
        "data": fields
    }