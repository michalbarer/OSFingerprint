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
        self.ip_ids = []

    def send_probe(self):
        for config in self.probe_configs:
            ip_packet = IP(dst=self.target_ip, tos=config["tos"])
            icmp_packet = ICMP(type="echo-request", code=config["code"], seq=config["seq_num"])
            payload = bytes([0x00] * config["payload_size"])
            packet = ip_packet / icmp_packet / payload

            self.sent_ttl = packet[IP].ttl
            response = sr1(packet, timeout=1, verbose=0)
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
                    "df": "DF" in ip_layer.flags,
                    "ttl": ip_layer.ttl,
                    "probe_code": self.probe_configs[i]["code"],
                    "response_code": icmp_layer.code if icmp_layer else None,
                })

                if not response_data["icmp_u1_response"]:
                    response_data["icmp_u1_response"] = {"ttl": ip_layer.ttl}
            else:
                response_data["icmp_responses"].append(None)

        return response_data

    def analyze_response(self):
        for i, response in enumerate(self.responses, start=1):
            if response:
                print(f"ICMP Echo Probe {i} Response: {response.summary()}")
            else:
                print(f"ICMP Echo Probe {i} received no response.")
