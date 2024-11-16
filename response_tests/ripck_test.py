from response_tests.base_response_test import ResponseTest


class IntegrityReturnedIPChecksumTest(ResponseTest):
    """
    Integrity of Returned Probe IP Checksum Value (RIPCK) Test.
    Checks the integrity of the IP checksum in the ICMP response.
    - G (Good): Checksum matches the enclosing IP packet.
    - Z: Checksum is zero.
    - I (Invalid): Checksum does not match.
    """

    def analyze(self):
        """
        Analyzes the returned IP checksum value.
        """
        ip_checksum = self.response_data.get("ip_checksum")

        if ip_checksum is None:
            print("No IP checksum data available for analysis.")
            return None

        if ip_checksum == 0:
            result = "Z"  # Zero checksum
        elif self.response_data.get("is_valid_ip_checksum", False):
            result = "G"  # Good checksum
        else:
            result = "I"  # Invalid checksum

        print(f"Integrity of Returned Probe IP Checksum Value (RIPCK): {result}")
        return result
