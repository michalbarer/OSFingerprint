import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class TCPFlagProbe(Probe):
    """
    Sends the TCP Flag Probes (T2-T7) for OS fingerprinting.
    """
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)
        self.probe_configs = [
            {'flags': '', 'window': 128},    # T2 - Null flag
            {'flags': 'SFUP', 'window': 256}, # T3 - SYN, FIN, URG, PSH
            {'flags': 'A', 'window': 1024},   # T4 - ACK
            {'flags': 'S', 'window': 31337},  # T5 - SYN
            {'flags': 'A', 'window': 32768},  # T6 - ACK
            {'flags': 'FPU', 'window': 65535} # T7 - FIN, PSH, URG
        ]

    def send_probe(self):
        self.responses = []
        for config in self.probe_configs:
            ip_packet = IP(dst=self.target_ip)
            tcp_packet = TCP(dport=self.target_port, flags=config['flags'], window=config['window'])
            packet = ip_packet / tcp_packet
            response = sr1(packet, timeout=1, verbose=0)
            self.responses.append(response)
            time.sleep(0.1)

    def analyze_response(self):
        for i, response in enumerate(self.responses, start=2):
            if response:
                print(f"TCP Flag Probe T{i} Response:", response.summary())
            else:
                print(f"TCP Flag Probe T{i} received no response.")
