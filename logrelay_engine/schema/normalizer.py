import ipaddress
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from logrelay_engine.schema.models import EventType, IPRegistry, SecurityEvent, User


APACHE_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<user_agent>[^"]*)"'
)

STATUS_DESCRIPTIONS = {
    200: ("OK", "USER"),
    201: ("Created", "USER"),
    301: ("Moved Permanently", "USER"),
    302: ("Found", "USER"),
    400: ("Bad Request", "ANONYMOUS"),
    401: ("Unauthorized", "ANONYMOUS"),
    403: ("Forbidden", "ANONYMOUS"),
    404: ("Not Found", "ANONYMOUS"),
    500: ("Internal Server Error", "USER"),
}


class LogNormalizer:
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.ip_registry: Dict[str, IPRegistry] = {}
        self.event_types: Dict[str, EventType] = {}
        self.events: List[SecurityEvent] = []
        self._user_id_seq = 1
        self._event_id_seq = 1

    def _parse_timestamp(self, ts_str: str) -> datetime:
        clean_ts = ts_str.split()[0]
        return datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")

    def _get_subnet(self, ip_str: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version == 4:
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                return str(network)
            return "IPV6_SUBNET"
        except ValueError:
            return "UNKNOWN_SUBNET"

    def normalize_line(self, raw_line: str) -> Optional[SecurityEvent]:
        match = APACHE_LOG_PATTERN.match(raw_line.strip())
        if not match:
            return None

        data = match.groupdict()
        ip = data["ip"]
        raw_user = data["user"]
        status = int(data["status"])
        path = data["path"]
        user_agent = data["user_agent"]
        timestamp = self._parse_timestamp(data["time"])

        username = raw_user if raw_user != "-" else f"anon_{ip.replace('.', '_')}"
        default_desc, default_role = STATUS_DESCRIPTIONS.get(
            status, ("HTTP_EVENT", "ANONYMOUS")
        )

        ua_lower = user_agent.lower()
        if "curl" in ua_lower or "python" in ua_lower or "bot" in ua_lower:
            role = "BOT"
        elif path.startswith("/admin"):
            role = "ADMIN"
        else:
            role = default_role

        if username not in self.users:
            user = User(
                user_id=self._user_id_seq, username=username, access_level=role
            )
            user.validate()
            self.users[username] = user
            self._user_id_seq += 1
        user_id = self.users[username].user_id

        if ip not in self.ip_registry:
            subnet = self._get_subnet(ip)
            ip_entry = IPRegistry(
                ip_address=ip, subnet=subnet, geo_location="LOCAL"
            )
            ip_entry.validate()
            self.ip_registry[ip] = ip_entry

        type_code = f"HTTP_{status}"
        if type_code not in self.event_types:
            event_type = EventType(
                type_code=type_code,
                http_status=status,
                description=default_desc,
            )
            event_type.validate()
            self.event_types[type_code] = event_type

        event = SecurityEvent(
            event_id=self._event_id_seq,
            timestamp=timestamp,
            user_id=user_id,
            ip_address=ip,
            type_code=type_code,
            path=path,
            user_agent=user_agent,
        )
        event.validate()
        self.events.append(event)
        self._event_id_seq += 1
        return event

    def normalize_file(
        self, filepath: str
    ) -> Tuple[
        List[User], List[IPRegistry], List[EventType], List[SecurityEvent]
    ]:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                self.normalize_line(line)
        return (
            list(self.users.values()),
            list(self.ip_registry.values()),
            list(self.event_types.values()),
            self.events,
        )