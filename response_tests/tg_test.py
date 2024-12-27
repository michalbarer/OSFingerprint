from response_tests.base_response_test import ResponseTest


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
            print("No observed TTL available, unable to guess initial TTL.")
            return None

        # Define common initial TTL values used by systems
        common_ttl_values = [32, 64, 128, 255]

        for ttl in common_ttl_values:
            if observed_ttl <= ttl:
                print(f"Guessed Initial TTL (TG): {ttl}")
                return ttl

        print("Guessed Initial TTL (TG): 255")
        return 255
