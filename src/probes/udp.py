import random

from scapy.layers.inet import IP, UDP, ICMP, IPerror, UDPerror
from scapy.sendrecv import sr1

from src.probes.base_probe import Probe


class UDPProbe(Probe):
    """
    Sends the UDP (U1) probe to a closed port.
    """

    def send_probe(self):
        ip_packet = IP(dst=self.target_ip, id=1042)
        udp_packet = UDP(dport=self.target_port, sport=random.randint(60000, 65535))
        payload = b'C' * 300
        packet = ip_packet / udp_packet / payload
        self.sent_ttl = packet[IP].ttl

        # Get checksums before sending the packet
        del packet.chksum
        packet = packet.__class__(bytes(packet))
        self.sent_ip_chksum = packet[IP].chksum
        self.sent_udp_chksum = packet[UDP].chksum

        self.response = sr1(packet, timeout=2, verbose=0)

    def get_response_data(self):
        response_data = {
            "response_received": bool(self.response),
            "sent_ttl": self.sent_ttl,
            "response_ttl": None,
            "ip_total_length": None,
            "ip_id": None,
            "ip_checksum": self.sent_ip_chksum,
            "returned_ip_checksum": None,
            "unused_field": None,
            "udp_checksum": self.sent_udp_chksum,
            "returned_udp_checksum": None,
            "udp_payload": None,
            "returned_ip_total_length": None,
            "flags": None
        }

        if self.response:
            ip_layer = self.response.getlayer(IP)
            if ip_layer:
                response_data["flags"] = str(ip_layer.flags)
                response_data["response_ttl"] = ip_layer.ttl
                response_data["ip_total_length"] = ip_layer.len
                response_data["ip_id"] = ip_layer.id

            if self.response.haslayer(ICMP) and self.response.getlayer(ICMP).type == 3:
                icmp_layer = self.response.getlayer(ICMP)
                response_data["unused_field"] = icmp_layer.unused

            udp_error_layer = self.response.getlayer(UDPerror)
            if udp_error_layer:
                response_data["returned_udp_checksum"] = udp_error_layer.chksum
                response_data["udp_payload"] = udp_error_layer.payload

            ip_error_layer = self.response.getlayer(IPerror)
            if ip_error_layer:
                response_data["returned_ip_total_length"] = ip_error_layer.len
                response_data["returned_ip_id"] = ip_error_layer.id
                response_data["returned_ip_checksum"] = ip_error_layer.chksum

        return response_data
