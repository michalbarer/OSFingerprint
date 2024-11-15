import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class TCPProbe(Probe):
    """
    Sends the TCP Flag Probes (T2-T7) for OS fingerprinting.
    """

    def __init__(self, target_ip, open_port, closed_port):
        super().__init__(target_ip)
        self.open_port = open_port
        self.closed_port = closed_port  # todo - do we really need open & closed ports
        self.probe_configs = [
            {"flags": "", "df": True, "window": 128, "port": self.open_port},  # T2 - Null flag
            {"flags": "SFUP", "df": False, "window": 256, "port": self.open_port},  # T3 - SYN, FIN, URG, PSH
            {"flags": "A", "df": True, "window": 1024, "port": self.open_port},  # T4 - ACK
            {"flags": "S", "df": False, "window": 31337, "port": self.closed_port},  # T5 - SYN
            {"flags": "A", "df": True, "window": 32768, "port": self.closed_port},  # T6 - ACK
            {"flags": "FPU", "df": False, "window": 65535, "port": self.closed_port}  # T7 - FIN, PSH, URG
        ]
        self.responses = []

    def send_probe(self):
        for config in self.probe_configs:
            ip_packet = IP(dst=self.target_ip)
            tcp_packet = TCP(
                dport=config["port"],
                flags=config["flags"],
                window=config["window"],
                options=[
                    ("WScale", 15),
                    ("NOP", None),
                    ("MSS", 265),
                    ("Timestamp", (0xFFFFFFFF, 0)),
                    ("SAckOK", b"")
                ]
            )
            packet = ip_packet / tcp_packet
            response = sr1(packet, timeout=1, verbose=0)
            self.responses.append(response)
            time.sleep(0.1)

    def get_response_data(self):
        pass

    def analyze_response(self):
        for i, response in enumerate(self.responses, start=2):
            if response and TCP in response:
                tcp_layer = response[TCP]
                print(f"TCP Flag Probe T{i} Response:", response.summary())
                print(f"  Flags: {tcp_layer.flags}")
                print(f"  Window Size: {tcp_layer.window}")
            else:
                print(f"TCP Flag Probe T{i} received no response.")
