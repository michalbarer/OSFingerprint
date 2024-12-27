import logging
import random
import time
from typing import Optional, List

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

Logger = logging.getLogger(__name__)

def port_scanner(host: str,
                 # open_ports: List[int], closed_ports: List[int],
                 start_port: Optional[int], end_port: Optional[int], time_limit: int = 30):
    """
    A port scanner with a time limit.

    Args:
        host (str): the host
        open_ports (list): list of open ports
        closed_ports (list): list of closed ports
        start_port (int): start of the port range
        end_port (int): end of the port range
        time_limit (int): time limit for the scan in seconds. Default is 30 seconds.
    Returns:
        tuple: A tuple of lists containing open and closed ports.
    """
    # ports_to_scan = open_ports + closed_ports
    ports_to_scan = []
    validated_open_ports = []
    validated_closed_ports = []

    if not start_port:
        start_port = 0
    if not end_port:
        end_port = 65535

    ports_to_scan += [*range(start_port, end_port + 1)]
    start_time = time.time()

    for port in ports_to_scan:
        if time.time() - start_time > time_limit:
            Logger.warning("Time limit exceeded. Returning results found so far.")
            break

        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0
        )

        if resp and resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                validated_open_ports.append(port)
            elif resp.getlayer(TCP).flags == 0x14:
                validated_closed_ports.append(port)

    return validated_open_ports, validated_closed_ports


if __name__ == "__main__":
    host = "10.100.102.7"
    start_port = 8070
    end_port = 8090
    limit = 30

    result = port_scanner(host, range(start_port, end_port), limit)

    print(f"Open Ports: {result[0]}")
    print(f"Closed Ports: {result[1]}")
