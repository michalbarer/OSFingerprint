from random import randint

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class ICMPEchoProbe(Probe):
    """
    Sends the ICMP Echo (IE) probe for OS fingerprinting.
    """
    def send_probe(self):
        ip_packet = IP(dst=self.target_ip)
        icmp_packet = ICMP(type="echo-request", seq=295, id=randint(0, 65535))
        self.response = sr1(ip_packet / icmp_packet, timeout=1, verbose=0)

    def analyze_response(self):
        if self.response:
            print("ICMP Echo Probe Response:", self.response.summary())
        else:
            print("ICMP Echo Probe received no response.")
