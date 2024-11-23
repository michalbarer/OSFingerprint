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
        self.ip_ids = []
        self.timestamps = []
        self.sent_ttls = []
        self.timestamp_vals = []

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
                             )
            packet = ip_packet / tcp_packet
            self.sent_ttls.append(packet[IP].ttl)
            response = sr1(packet, timeout=1, verbose=0)
            if response and TCP in response:
                self.isns.append(response[TCP].seq)
                self.ip_ids.append(response[IP].id)
                self.timestamps.append(time.time())
                tcp_options = response[TCP].options
                tsval = self._extract_tsval(tcp_options)
                if tsval is not None:
                    self.timestamp_vals.append(tsval)
            self.responses.append(response)
            time.sleep(0.1)  # 100 ms delay between probes

    @staticmethod
    def _extract_tsval(options):
        """
        Extracts the TSval (TCP timestamp value) from the TCP options.
        :param options: TCP options list
        :return: TSval if present, None otherwise
        """
        for opt in options:
            if opt[0] == "Timestamp" and len(opt[1]) >= 1:
                return opt[1][0]  # Return TSval (the first value in the Timestamp tuple)
        return None

    def get_response_data(self):
        """
        Returns a dictionary of response data including ISNs.
        """
        return {
            "isns": self.isns,
            "timestamps": self.timestamps,
            "response_received": any(self.responses),
            "ip_ids": self.ip_ids,
            "timestamp_vals": self.timestamp_vals
        }

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

    def get_response_data(self):
        response_data = {}

        for i, response in enumerate(self.responses, start=1):
            if response and TCP in response:
                tcp_layer = response[TCP]
                response_data[f"tcp_options_{i}"] = []
                for option in tcp_layer.options:
                    if isinstance(option, tuple):
                        response_data[f"tcp_options_{i}"].append(option)

        return response_data

class WINProbe(TCPSequenceProbe):
    """ TCP Sequence Probe WIN """

    def get_response_data(self):
        response_data = {}

        for i, response in enumerate(self.responses, start=1):
            if response and TCP in response:
                tcp_layer = response[TCP]
                response_data[f"tcp_window_size_{i}"] = tcp_layer.window

        return response_data

class T1Probe(TCPSequenceProbe):
    """ TCP Sequence Probe T1 """
    def get_response_data(self):
        response_data = {
            "response_received": bool(self.responses[0]),
            "ip": self.responses[0][IP] if self.responses[0] else None,
            "flags": None,
            "sent_ttl": self.sent_ttls[0],
            "icmp_u1_response": None,
            "sequence_number": None,
            "ack_number": None,
            "data": b"",
            "reserved_field": 0,
            "urgent_pointer": 0,
            "urg_flag_set": False,
        }

        if self.responses[0]:
            ip_layer = self.responses[0].getlayer(IP)
            if ip_layer:
                response_data["icmp_u1_response"] = {"ttl": ip_layer.ttl}
            if TCP in self.responses[0]:
                response = self.responses[0][TCP]
                response_data["flags"] = response.flags
                response_data["sequence_number"] = response.seq
                response_data["ack_number"] = response.ack
                response_data["data"] = bytes(response.payload)
                response_data["reserved_field"] = (response.reserved >> 4) & 0x07
                response_data["urgent_pointer"] = response.urgptr
                response_data["urg_flag_set"] = bool(
                    response.flags & 0x20
                )

        return response_data
