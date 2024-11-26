from response_tests.base_response_test import ResponseTest


class ReturnedProbeIPTotalLengthTest(ResponseTest):
    """
    Returned Probe IP Total Length Value (RIPL) Test.
    Records the returned IP total length value from the ICMP port unreachable message.
    If the value is 0x148 (328), 'G' (for good) is stored instead of the actual value.
    """

    def analyze(self):
        """
        Analyzes the returned IP total length value from the ICMP response.
        """
        # Retrieve the returned IP total length value from the response data
        returned_length = self.response_data.get("returned_ip_total_length")

        if returned_length is None:
            print("No returned IP total length data available for analysis.")
            return None

        # If the value is 0x148 (328), record 'G' for good
        if returned_length == 0x148:  # Hexadecimal 328
            print("Returned Probe IP Total Length (RIPL): G")
            return "G"

        # Otherwise, record the actual returned value
        print(f"Returned Probe IP Total Length (RIPL): {returned_length}")
        return returned_length
