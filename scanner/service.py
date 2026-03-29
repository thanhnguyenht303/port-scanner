import socket


def get_service_name(port: int) -> str:
    """
    Return the common TCP service name for a port if known.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"