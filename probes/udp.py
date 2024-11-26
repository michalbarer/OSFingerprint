from sys import flags

from scapy.layers.inet import IP, UDP, ICMP, IPerror, UDPerror
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
        self.sent_ttl = packet[IP].ttl
        self.response = sr1(packet, timeout=2, verbose=0)

    def get_response_data(self):
        response_data = {
            "response_received": bool(self.response),
            "sent_ttl": self.sent_ttl,
            "icmp_u1_response": None,
            "ip_total_length": None,
            "ip_id": None,
            "ip_checksum": None,
            "unused_field": None,
            "udp_checksum": None,
            "udp_payload": None,
            "returned_ip_total_length": None,
            "flags": None
        }

        if self.response:
            ip_layer = self.response.getlayer(IP)
            if ip_layer:
                response_data["flags"] = ip_layer.flags
                response_data["icmp_u1_response"] = {"ttl": ip_layer.ttl}
                response_data["ip_total_length"] = ip_layer.len
                response_data["ip_id"] = ip_layer.id
                response_data["ip_checksum"] = ip_layer.chksum

            # Check if the response is an ICMP message (port unreachable)
            if self.response.haslayer(ICMP) and self.response.getlayer(ICMP).type == 3:
                icmp_layer = self.response.getlayer(ICMP)
                response_data["unused_field"] = icmp_layer.unused

            udp_layer = self.response.getlayer(UDP)
            if udp_layer:
                response_data["udp_checksum"] = udp_layer.chksum
                response_data["udp_payload"] = udp_layer.payload

            ip_error_layer = self.response.getlayer(IPerror)
            if ip_error_layer:
                response_data["returned_ip_total_length"] = ip_error_layer.len
                response_data["returned_ip_id"] = ip_error_layer.id

        # todo: check how to return data for RIPCK, RUCK, RUD
        return response_data

    def analyze_response(self):
        if self.response:
            print("UDP Probe Response:", self.response.summary())
        else:
            print("UDP Probe received no response.")