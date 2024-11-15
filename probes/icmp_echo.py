import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class ICMPEchoProbe(Probe):
    """
    Sends the ICMP Echo (IE) probe for OS fingerprinting.
    """
    def __init__(self, target_ip):
        super().__init__(target_ip)
        self.probe_configs = [
            {"tos": 0, "code": 9, "seq_num": 295, "payload_size": 120},
            {"tos": 4, "code": 0, "seq_num": 296, "payload_size": 150},
        ]
        self.responses = []

    def send_probe(self):
        for config in self.probe_configs:
            ip_packet = IP(dst=self.target_ip, tos=config["tos"])
            icmp_packet = ICMP(type="echo-request", code=config["code"], seq=config["seq_num"])
            payload = bytes([0x00] * config["payload_size"])
            packet = ip_packet / icmp_packet / payload

            response = sr1(packet, timeout=1, verbose=0)

            self.responses.append(response)
            time.sleep(0.1)  # 100 ms delay between probes

    def get_response_data(self):
        pass

    def analyze_response(self):
        for i, response in enumerate(self.responses, start=1):
            if response:
                print(f"ICMP Echo Probe {i} Response: {response.summary()}")
            else:
                print(f"ICMP Echo Probe {i} received no response.")
