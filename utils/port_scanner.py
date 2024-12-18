import logging
import random
import time
from venv import logger

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

logger = logging.getLogger(__name__)
def port_scanner(host: str, port_range: range, time_limit: int = 30):
    """
    A port scanner with a time limit.

    Args:
        host (str): the host
        port_range (range): port range to check
        time_limit (int): time limit for the scan in seconds. Default is 30 seconds.
    Returns:
        tuple: A tuple of lists containing open and closed ports.
    """
    open_ports = []
    closed_ports = []
    start_time = time.time()

    for port in port_range:
        if time.time() - start_time > time_limit:
            logger.warning("Time limit exceeded. Returning results found so far.")
            break

        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0
        )

        if resp and resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
            elif resp.getlayer(TCP).flags == 0x14:
                closed_ports.append(port)

    return open_ports, closed_ports


if __name__ == "__main__":
    host = "10.100.102.7"
    start_port = 8070
    end_port = 8090
    limit = 30

    result = port_scanner(host, range(start_port, end_port), limit)

    print(f"Open Ports: {result[0]}")
    print(f"Closed Ports: {result[1]}")
