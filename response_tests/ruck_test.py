from response_tests.base_response_test import ResponseTest


class IntegrityReturnedUDPChecksumTest(ResponseTest):
    """
    Integrity of Returned Probe UDP Checksum (RUCK) Test.
    Checks the integrity of the UDP header checksum in the ICMP response.
    - G: Checksum matches the original probe.
    - Otherwise: The returned checksum value is recorded.
    """

    def analyze(self):
        """
        Analyzes the returned UDP checksum value.
        """
        udp_checksum = self.response_data.get("udp_checksum")

        if udp_checksum is None:
            print("No UDP checksum data available for analysis.")
            return None

        if self.response_data.get("is_valid_udp_checksum", False):
            result = "G"  # Good checksum #
        else:
            result = udp_checksum  # Return the actual checksum value

        print(f"Integrity of Returned Probe UDP Checksum Value (RUCK): {result}")
        return result
