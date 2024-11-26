import socket
from typing import Optional


def get_open_and_closed_port(host: str, ports: range) -> tuple[Optional[int], Optional[int]]:
    """
    Scans the specified ports on the given host and returns the first open and closed ports.

    Parameters:
        host (str): The hostname or IP address to scan.
        ports (range): A range of ports to scan.

    Returns:
        tuple: A tuple containing:
               - The first open port (or None if none found)
               - The first closed port (or None if none found)
    """
    # todo: this implementation is lacking - filtered ports are considered as closed ports
    open_port = None
    closed_port = None

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0 and open_port is None:
                open_port = port
            elif result != 0 and closed_port is None:
                closed_port = port

            if open_port is not None and closed_port is not None:
                break

    return open_port, closed_port


if __name__ == "__main__":
    host = "ynet.co.il"
    ports = range(20, 1025)
    open_port, closed_port = get_open_and_closed_port(host, ports)

    print(f"First Open Port: {open_port}")
    print(f"First Closed Port: {closed_port}")
