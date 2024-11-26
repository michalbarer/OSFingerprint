import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class TCPProbe(Probe):
    """
    Sends the TCP Flag Probes (T2-T7) for OS fingerprinting.
    """

    def __init__(self, target_ip):
        super().__init__(target_ip)
        self.probe_config = {}
        self.sent_ttl = None

    def send_probe(self):
        if self.probe_config:
            ip_packet = IP(dst=self.target_ip)
            tcp_packet = TCP(
                dport=self.probe_config["port"],
                flags=self.probe_config["flags"],
                window=self.probe_config["window"],
                options=[
                    ("WScale", 10),
                    ("NOP", None),
                    ("MSS", 265),
                    ("Timestamp", (0xFFFFFFFF, 0)),
                    ("SAckOK", b"")
                ]
            )

            packet = ip_packet / tcp_packet
            self.sent_ttl = packet[IP].ttl
            self.response = sr1(packet, timeout=1, verbose=0)
            time.sleep(0.1)

    def get_response_data(self):
        response_data = {
            "ip_id": None,
            "response_received": bool(self.response),
            "flags": None,
            "sent_ttl": self.sent_ttl,
            "icmp_u1_response": None,
            "sequence_number": None,
            "ack_number": None,
            "data": b"",
            "reserved_field": 0,
            "urgent_pointer": 0,
            "urg_flag_set": False,
            "tcp_window_size": None,
            "tcp_options": [],
        }

        if self.response:
            if "IP" in self.response:
                response_data["ip_id"] = self.response["IP"].id
            ip_layer = self.response.getlayer(IP)
            if ip_layer:
                response_data["icmp_u1_response"] = {"ttl": ip_layer.ttl}
            if TCP in self.response:
                tcp_layer = self.response[TCP]
                response_data["flags"] = tcp_layer.flags
                response_data["sequence_number"] = tcp_layer.seq
                response_data["ack_number"] = tcp_layer.ack
                response_data["data"] = bytes(tcp_layer.payload)  # Extract raw data
                response_data["tcp_window_size"] = tcp_layer.window

                # Extract the reserved field (bits 7-4 of the data offset)
                response_data["reserved_field"] = (tcp_layer.reserved >> 4) & 0x07

                # Extract the urgent pointer and check if the URG flag is set
                response_data["urgent_pointer"] = tcp_layer.urgptr
                response_data["urg_flag_set"] = bool(
                    tcp_layer.flags & 0x20
                )  # Check if the URG flag is set (0x20 is the URG flag bit)

                # Extract TCP options and add to response_data
                response_data["tcp_options"] = tcp_layer.options
        return response_data

    def analyze_response(self):
        if self.response and TCP in self.response:
            tcp_layer = self.response[TCP]
            print(f"TCP Flag Probe {self.__class__.__name__}: {self.response.summary()}")
            print(f"  Flags: {tcp_layer.flags}")
            print(f"  Window Size: {tcp_layer.window}")
        else:
            print(f"TCP Flag Probe {self.__class__.__name__} received no response.")


class T2Probe(TCPProbe):
    """ TCP Flag Probe T2 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip)
        self.open_port = open_port
        self.probe_config = {"flags": "", "df": True, "window": 128, "port": self.open_port}


class T3Probe(TCPProbe):
    """ TCP Flag Probe T3 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip)
        self.open_port = open_port
        self.probe_config = {"flags": "SFUP", "df": False, "window": 256, "port": self.open_port}


class T4Probe(TCPProbe):
    """ TCP Flag Probe T4 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip)
        self.open_port = open_port
        self.probe_config = {"flags": "A", "df": True, "window": 1024, "port": self.open_port}


class T5Probe(TCPProbe):
    """ TCP Flag Probe T5 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip)
        self.closed_port = closed_port
        self.probe_config = {"flags": "S", "df": False, "window": 31337, "port": self.closed_port}


class T6Probe(TCPProbe):
    """ TCP Flag Probe T6 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip)
        self.closed_port = closed_port
        self.probe_config = {"flags": "A", "df": True, "window": 32768, "port": self.closed_port}


class T7Probe(TCPProbe):
    """ TCP Flag Probe T7 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip)
        self.closed_port = closed_port
        self.probe_config = {"flags": "FPU", "df": False, "window": 65535, "port": self.closed_port}
