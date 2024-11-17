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
        self.closed_port = closed_port
        self.probe_config = {}
        self.responses = []

    def send_probe(self):
        if self.probe_config:
            ip_packet = IP(dst=self.target_ip)
            tcp_packet = TCP(
                dport=self.probe_config["port"],
                flags=self.probe_config["flags"],
                window=self.probe_config["window"],
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
        return [{"response_received": bool(response)} for response in self.responses]

    def analyze_response(self):
        for i, response in enumerate(self.responses, start=2):
            if response and TCP in response:
                tcp_layer = response[TCP]
                print(f"TCP Flag Probe T{i} Response:", response.summary())
                print(f"  Flags: {tcp_layer.flags}")
                print(f"  Window Size: {tcp_layer.window}")
            else:
                print(f"TCP Flag Probe T{i} received no response.")


class T2Probe(TCPProbe):
    """ TCP Flag Probe T2 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip, open_port, None)
        self.probe_configs = {"flags": "", "df": True, "window": 128, "port": self.open_port}


class T3Probe(TCPProbe):
    """ TCP Flag Probe T3 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip, open_port, None)
        self.probe_configs = {"flags": "SFUP", "df": False, "window": 256, "port": self.open_port}


class T4Probe(TCPProbe):
    """ TCP Flag Probe T4 """
    def __init__(self, target_ip, open_port):
        super().__init__(target_ip, open_port, None)
        self.probe_configs = {"flags": "A", "df": True, "window": 1024, "port": self.open_port}


class T5Probe(TCPProbe):
    """ TCP Flag Probe T5 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip, None, closed_port)
        self.probe_config = {"flags": "S", "df": False, "window": 31337, "port": self.closed_port}


class T6Probe(TCPProbe):
    """ TCP Flag Probe T6 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip, None, closed_port)
        self.probe_config = {"flags": "A", "df": True, "window": 32768, "port": self.closed_port}


class T7Probe(TCPProbe):
    """ TCP Flag Probe T7 """
    def __init__(self, target_ip, closed_port):
        super().__init__(target_ip, None, closed_port)
        self.probe_config = {"flags": "FPU", "df": False, "window": 65535, "port": self.closed_port}
