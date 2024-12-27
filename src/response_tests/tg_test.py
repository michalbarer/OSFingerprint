from src.response_tests.base_response_test import ResponseTest


class IPInitialTTLGuessTest(ResponseTest):
    """
    IP Initial Time-to-Live Guess (TG) Test.
    Makes an educated guess about the initial TTL value when no response is received.
    """

    def analyze(self):
        """
        Analyzes the response data and guesses the initial TTL value.
        """
        icmp_response = self.response_data.get("icmp_u1_response")
        observed_ttl = icmp_response["ttl"] if icmp_response else None

        if observed_ttl is None:
            return None

        # Common initial TTL values
        common_ttl_values = [32, 64, 128, 255]

        for ttl in common_ttl_values:
            if observed_ttl <= ttl:
                return ttl

        return 255
