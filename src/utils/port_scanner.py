import logging
import random
from typing import List, Optional

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

Logger = logging.getLogger(__name__)

COMMON_PORTS = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle Database",
    1723: "PPTP",
    1812: "RADIUS Authentication",
    1813: "RADIUS Accounting",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion (SVN)",
    4333: "mSQL",
    5432: "PostgreSQL",
    5500: "VNC",
    5631: "pcAnywhere",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    8000: "HTTP Dev Server",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternate",
    8888: "HTTP Alternate",
    9200: "Elasticsearch",
    9300: "Elasticsearch Node Communication",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB Shard",
    27019: "MongoDB Config Server",
    50000: "SAP",
    50070: "Hadoop HDFS"
}

def port_scanner(host: str,
                 open_ports: Optional[List[int]] = None,
                 closed_ports: Optional[List[int]] = None) -> tuple:
    """
    A port scanner with a time limit.

    Args:
        host (str): the host
        open_ports (list): list of open ports
        closed_ports (list): list of closed ports
    Returns:
        tuple: A tuple of lists containing open and closed ports.
    """
    if not open_ports:
        open_ports = []
    if not closed_ports:
        closed_ports = []

    ports_to_scan = open_ports + closed_ports
    ports_to_scan += list(COMMON_PORTS.keys())

    validated_open_ports = []
    validated_closed_ports = []

    for port in ports_to_scan:

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
