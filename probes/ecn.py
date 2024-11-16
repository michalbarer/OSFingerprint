from random import randint

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class ExplicitCongestionNotificationProbe(Probe):
    """
    Sends the TCP Explicit Congestion Notification (ECN) probe.
    """

    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)
        self.response = None

    def send_probe(self):
        ip_packet = IP(dst=self.target_ip)
        tcp_packet = TCP(
            dport=self.target_port,
            flags="SCE",
            seq=randint(0, 65535),
            ack=0,
            window=3,
            options=[
                ("WScale", 10),
                ("NOP", None),
                ("MSS", 1460),
                ("SAckOK", b'')
            ]
        )
        packet = ip_packet / tcp_packet
        self.response = sr1(packet, timeout=1, verbose=0)

    def get_response_data(self):
        if not self.response:
            return {"response_received": False}

        ip_layer = self.response.getlayer(IP)
        return {
            "ip": {
                "flags": ip_layer.flags
            },
            "response_received": bool(self.response)
        }

    def analyze_response(self):
        if self.response and TCP in self.response:
            tcp_layer = self.response[TCP]
            print(f"ECN Probe Response: {self.response.summary()}")
            print(f"Flags: {tcp_layer.flags}, Window Size: {tcp_layer.window}")
        else:
            print("ECN Probe received no response.")
