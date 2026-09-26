import re

from parsers.base import BaseParser


class SyslogParser(BaseParser):

    def name(self) -> str:
        return "syslog_v1"

    def parse(self, raw_log: str) -> dict:
        raw_log = raw_log.strip()

        # 1. RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PID MSGID MSG
        rfc5424_pattern = r"^<(?P<priority>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>[\w\.\-]+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+-\s+(?P<message>.*)$"
        m = re.match(rfc5424_pattern, raw_log)
        if m:
            return {
                "parser": self.name(),
                "format": "SYSLOG",
                "data": m.groupdict()
            }

        # 2. RFC 3164 with priority: <PRI>Month Day HH:MM:SS host message
        rfc3164_pri = r"^<(?P<priority>\d+)>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$"
        m = re.match(rfc3164_pri, raw_log)
        if m:
            return {
                "parser": self.name(),
                "format": "SYSLOG",
                "data": m.groupdict()
            }

        # 3. RFC 3164 without priority: Month Day HH:MM:SS host message
        rfc3164_nopri = r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$"
        m = re.match(rfc3164_nopri, raw_log)
        if m:
            data = m.groupdict()
            data["priority"] = 134  # Default facility=user, severity=info
            return {
                "parser": self.name(),
                "format": "SYSLOG",
                "data": data
            }

        raise ValueError("Invalid Syslog format")