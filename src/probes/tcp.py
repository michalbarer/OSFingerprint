import random
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
        self.src_port = random.randint(60000, 65535)
        self.seq = 0
        self.ack = 0
        self.ip_packet = None
        self.tcp_packet = None

    def send_probe(self):
        if self.ip_packet and self.tcp_packet:
            packet = self.ip_packet / self.tcp_packet
            self.sent_ttl = packet[IP].ttl
            self.response = sr1(packet, timeout=2, verbose=0)
            time.sleep(0.1)

    def get_response_data(self):
        response_data = {
            "ip_id": None,
            "response_received": bool(self.response),
            "flags": None,
            "df_flag_set": None,
            "sent_ttl": self.sent_ttl,
            "icmp_u1_response": None,
            "response_sequence_number": None,
            "probe_sequence_number": self.seq,
            "response_ack_number": None,
            "probe_ack_number": self.ack,
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
                response_data["df_flag_set"] = ip_layer.flags.DF
            if TCP in self.response:
                tcp_layer = self.response[TCP]
                response_data["flags"] = str(tcp_layer.flags)
                response_data["response_sequence_number"] = tcp_layer.seq
                response_data["response_ack_number"] = tcp_layer.ack
                response_data["data"] = bytes(tcp_layer.payload)
                response_data["tcp_window_size"] = tcp_layer.window
                response_data["reserved_field"] = tcp_layer.reserved
                response_data["urgent_pointer"] = tcp_layer.urgptr
                response_data["urg_flag_set"] = "U" in str(tcp_layer.flags)
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
        self.ip_packet = IP(dst=self.target_ip, flags="DF")
        self.tcp_packet = TCP(
            sport=self.src_port + 2,
            dport=self.open_port,
            window=128,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (0xFFFFFFFF, 0)),
                ("SAckOK", "")
            ],
            seq=self.seq,
            ack=self.ack
        )


class T3Probe(TCPProbe):
    """ TCP Flag Probe T3 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip)
        self.open_port = open_port
        self.ip_packet = IP(dst=self.target_ip)
        self.tcp_packet = TCP(
            sport=self.src_port + 3,
            dport=self.open_port,
            flags="SFUP",
            window=256,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (0xFFFFFFFF, 0)),
                ("SAckOK", "")
            ],
            seq=self.seq,
            ack=self.ack
        )


class T4Probe(TCPProbe):
    """ TCP Flag Probe T4 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip)
        self.open_port = open_port
        self.ip_packet = IP(dst=self.target_ip, flags="DF")
        self.tcp_packet = TCP(
            sport=self.src_port + 4,
            dport=self.open_port,
            flags="A",
            window=1024,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (0xFFFFFFFF, 0)),
                ("SAckOK", "")
            ],
            seq=self.seq,
            ack=self.ack
        )


class T5Probe(TCPProbe):
    """ TCP Flag Probe T5 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip)
        self.closed_port = closed_port
        self.ip_packet = IP(dst=self.target_ip)
        self.tcp_packet = TCP(
            sport=self.src_port + 5,
            dport=self.closed_port,
            flags="S",
            window=31337,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (0xFFFFFFFF, 0)),
                ("SAckOK", "")
            ],
            seq=self.seq,
            ack=self.ack
        )


class T6Probe(TCPProbe):
    """ TCP Flag Probe T6 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip)
        self.closed_port = closed_port
        self.ip_packet = IP(dst=self.target_ip, flags="DF")
        self.tcp_packet = TCP(
            sport=self.src_port + 6,
            dport=self.closed_port,
            flags="A",
            window=32768,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (0xFFFFFFFF, 0)),
                ("SAckOK", "")
            ],
            seq=self.seq,
            ack=self.ack
        )


class T7Probe(TCPProbe):
    """ TCP Flag Probe T7 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip)
        self.closed_port = closed_port
        self.ip_packet = IP(dst=self.target_ip)
        self.tcp_packet = TCP(
            sport=self.src_port + 7,
            dport=self.closed_port,
            flags="FPU",
            window=65535,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 265),
                ("Timestamp", (0xFFFFFFFF, 0)),
                ("SAckOK", "")
            ],
            seq=self.seq,
            ack=self.ack
        )
