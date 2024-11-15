from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class UDPProbe(Probe):
    """
    Sends the UDP (U1) probe to a closed port.
    """
    def send_probe(self):
        ip_packet = IP(dst=self.target_ip, id=0x1042)
        udp_packet = UDP(dport=self.target_port)
        payload = b'C' * 300
        packet = ip_packet / udp_packet / payload
        self.response = sr1(packet, timeout=2, verbose=0)

    def get_response_data(self):
        pass

    def analyze_response(self):
        if self.response:
            print("UDP Probe Response:", self.response.summary())
        else:
            print("UDP Probe received no response.")