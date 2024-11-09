from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class UDPProbe(Probe):
    """
    Sends the UDP (U1) probe to a closed port.
    """
    def send_probe(self):
        ip_packet = IP(dst=self.target_ip)
        udp_packet = UDP(dport=self.target_port)
        data = b'C' * 300
        packet = ip_packet / udp_packet / data
        self.response = sr1(packet, timeout=1, verbose=0)

    def analyze_response(self):
        if self.response:
            print("UDP Probe Response:", self.response.summary())
        else:
            print("UDP Probe received no response.")