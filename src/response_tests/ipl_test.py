from src.response_tests.base_response_test import ResponseTest


class IPTotalLengthTest(ResponseTest):
    """
    IP Total Length (IPL) Test.
    Records the total length (in octets) of an IP packet from the port unreachable
    response elicited by the U1 test.
    """

    def analyze(self):
        """
        Analyzes the port unreachable response to determine the IP total length.
        """
        ip_total_length = self.response_data.get("ip_total_length")

        if ip_total_length is None:
            return None

        return ip_total_length
