from response_tests.base_response_test import ResponseTest


class IPInitialTTLTest(ResponseTest):
    """
    IP Initial Time-to-Live (T) Test.
    Determines the initial TTL value of the target's IP packets based on the TTL
    observed in the ICMP Port Unreachable response to the U1 probe.
    """

    # todo: check implementation - returns sent ttl. Maybe we need to save response.ttl
    def analyze(self):
        """
        Analyzes the response to determine the initial TTL value.
        """
        # Retrieve the observed TTL from the ICMP Port Unreachable response
        icmp_response = self.response_data.get("icmp_u1_response")
        sent_ttl = self.response_data.get("sent_ttl")

        if not icmp_response or "ttl" not in icmp_response:
            print("No valid ICMP response data available for TTL analysis.")
            return None

        observed_ttl = icmp_response["ttl"]

        # Determine the hop distance (number of routers the packet traversed)
        hop_distance = sent_ttl - observed_ttl

        if hop_distance < 0:
            print("Warning: Negative hop distance indicates potential routing anomaly.")
            return None

        # Calculate the initial TTL value by adding the hop distance to the observed TTL
        initial_ttl = observed_ttl + hop_distance

        print(f"IP Initial Time-to-Live (T) Result: {initial_ttl}")
        return initial_ttl
