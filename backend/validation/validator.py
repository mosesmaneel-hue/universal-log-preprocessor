import ipaddress


def validate_ip(value):
    if not value:
        return True

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_port(value):
    if value is None:
        return True

    return isinstance(value, int) and 1 <= value <= 65535


def validate_event(event: dict) -> dict:

    errors = []

    source_ip = event.get("source", {}).get("ip")
    destination_ip = event.get("destination", {}).get("ip")

    source_port = event.get("source", {}).get("port")
    destination_port = event.get("destination", {}).get("port")

    if not validate_ip(source_ip):
        errors.append("Invalid source IP address")

    if not validate_ip(destination_ip):
        errors.append("Invalid destination IP address")

    if not validate_port(source_port):
        errors.append("Invalid source port")

    if not validate_port(destination_port):
        errors.append("Invalid destination port")

    return {
        "valid": len(errors) == 0,
        "errors": errors
    }