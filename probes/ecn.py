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
        self.sent_ttl = packet[IP].ttl
        self.response = sr1(packet, timeout=2, verbose=0)

    def get_response_data(self):
        response_data = {
            "response_received": bool(self.response),
            "sent_ttl": self.sent_ttl,
            "icmp_u1_response": None,
            "tcp_window_size": None,
            "tcp_options": [],
            "flags": None,
            "reserved_field": 0,
            "urgent_pointer": 0,
            "urg_flag_set": False,
            "df_flag_set": None,
        }

        if self.response:
            ip_layer = self.response.getlayer(IP)
            if ip_layer:
                response_data["icmp_u1_response"] = {"ttl": ip_layer.ttl}
                response_data["df_flag_set"] = ip_layer.flags.DF
            if TCP in self.response:
                tcp_layer = self.response[TCP]
                response_data["tcp_window_size"] = tcp_layer.window

                # Extract TCP options and add to response_data
                for option in tcp_layer.options:
                    if isinstance(option, tuple):
                        response_data["tcp_options"].append(option)

                response_data["flags"] = str(tcp_layer.flags)
                response_data["reserved_field"] = tcp_layer.reserved

                # Extract the urgent pointer and check if the URG flag is set
                response_data["urgent_pointer"] = tcp_layer.urgptr
                response_data["urg_flag_set"] = "U" in str(tcp_layer.flags)

        return response_data

    def analyze_response(self):
        if self.response and TCP in self.response:
            tcp_layer = self.response[TCP]
            print(f"ECN Probe Response: {self.response.summary()}")
            print(f"Flags: {tcp_layer.flags}, Window Size: {tcp_layer.window}")
        else:
            print("ECN Probe received no response.")
