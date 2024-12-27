import random
import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

from src.probes.base_probe import Probe


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
        self.ip_ids = []
        self.probe_df_flags = []

    def send_probe(self):
        ip_id = random.randint(0, 65534)
        icmp_id = random.randint(0, 65534)

        for config in self.probe_configs:
            ip_packet = IP(dst=self.target_ip, tos=config["tos"], id=ip_id)
            icmp_packet = ICMP(type="echo-request", code=config["code"], seq=config["seq_num"], id=icmp_id)
            payload = bytes([0x00] * config["payload_size"])
            packet = ip_packet / icmp_packet / payload

            self.sent_ttl = packet[IP].ttl
            self.probe_df_flags.append(packet[IP].flags.DF)
            response = sr1(packet, timeout=2, verbose=0)
            if response and IP in response:
                self.ip_ids.append(response[IP].id)

            self.responses.append(response)
            time.sleep(0.1)

    def get_response_data(self):
        response_data = {
            "ip_ids": self.ip_ids,
            "icmp_responses": [],
            "response_received": any(self.responses),
            "sent_ttl": self.sent_ttl,
            "icmp_u1_response": None,
        }

        for i, response in enumerate(self.responses):
            if response:
                ip_layer = response.getlayer(IP)
                icmp_layer = response.getlayer(ICMP)

                response_data["icmp_responses"].append({
                    "df": ip_layer.flags.DF,
                    "probe_df": self.probe_df_flags[i],
                    "ttl": ip_layer.ttl,
                    "probe_code": self.probe_configs[i]["code"],
                    "response_code": icmp_layer.code if icmp_layer else None,
                })

                if not response_data["icmp_u1_response"]:
                    response_data["icmp_u1_response"] = {"ttl": ip_layer.ttl}
            else:
                response_data["icmp_responses"].append({})

        return response_data
