from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class ExplicitCongestionNotificationProbe(Probe):
    """
    Sends the TCP Explicit Congestion Notification (ECN) probe.
    """
    def send_probe(self):
        ip_packet = IP(dst=self.target_ip)
        tcp_packet = TCP(dport=self.target_port, flags="S", window=3, options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', b'')])
        packet = ip_packet / tcp_packet
        self.response = sr1(packet, timeout=1, verbose=0)

    def analyze_response(self):
        if self.response:
            print("ECN Probe Response:", self.response.summary())
        else:
            print("ECN Probe received no response.")