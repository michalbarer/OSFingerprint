from src.response_tests.base_response_test import ResponseTest


class IPInitialTTLTest(ResponseTest):
    """
    IP Initial Time-to-Live (T) Test.
    Determines the initial TTL value of the target's IP packets based on the TTL
    observed in the ICMP Port Unreachable response to the U1 probe.
    """

    def analyze(self):
        """
        Analyzes the response to determine the initial TTL value.
        """
        response_ttl = self.response_data.get("response_ttl")
        sent_ttl = self.response_data.get("sent_ttl")

        if not response_ttl:
            return None

        hop_distance = sent_ttl - response_ttl

        if hop_distance < 0 or hop_distance > 255:
            return None

        initial_ttl = response_ttl + hop_distance
        if initial_ttl not in (64, 128, 255) and initial_ttl <= 255:
            initial_ttl = (initial_ttl + 63) // 64 * 64

        return initial_ttl if initial_ttl <= 255 else None