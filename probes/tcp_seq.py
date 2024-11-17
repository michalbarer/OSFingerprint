import os
import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from probes.base_probe import Probe


class TCPSequenceProbe(Probe):
    """
    Sends the TCP Sequence Probes (SEQ, OPS, WIN, T1) for OS fingerprinting.
    """
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)
        self.probe_configs = [
            {'window': 1, 'options': [('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')]},
            {'window': 63, 'options': [('MSS', 1400), ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]},
            {'window': 4, 'options': [('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)]},
            {'window': 4, 'options': [('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]},
            {'window': 16, 'options': [('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]},
            {'window': 512, 'options': [('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))]}
        ]
        self.responses = []
        self.isns = []
        self.timestamps = []

    def send_probe(self):
        """
        Sends all six TCP probes and collects ISNs.
        """
        for config in self.probe_configs:
            ip_packet = IP(dst=self.target_ip)
            tcp_packet = TCP(dport=self.target_port,
                             flags="S",
                             window=config['window'],
                             options=config['options'],
                             seq=int.from_bytes(os.urandom(4), 'big'),  # Randomize sequence number
                             ack=int.from_bytes(os.urandom(4), 'big')  # Randomize acknowledgment number
                             )
            packet = ip_packet / tcp_packet
            response = sr1(packet, timeout=1, verbose=0)
            if response and TCP in response:
                # Collect the Initial Sequence Number (ISN)
                self.isns.append(response[TCP].seq)
                self.timestamps.append(time.time())
            self.responses.append(response)
            time.sleep(0.1)  # 100 ms delay between probes

    def get_response_data(self):
        """
        Returns a dictionary of response data including ISNs.
        """
        return {"isns": self.isns, "timestamps": self.timestamps}

    def analyze_response(self):
        for i, response in enumerate(self.responses, start=1):
            if response:
                print(f"TCP Sequence Probe {i}: {response.summary()}")
            else:
                print(f"TCP Sequence Probe {i} received no response.")


class SEQProbe(TCPSequenceProbe):
    """ TCP Sequence Probe SEQ """
    pass

class OPSProbe(TCPSequenceProbe):
    """ TCP Sequence Probe OPS """
    pass

class WINProbe(TCPSequenceProbe):
    """ TCP Sequence Probe WIN """
    pass

class T1Probe(TCPSequenceProbe):
    """ TCP Sequence Probe T1 """
    pass
