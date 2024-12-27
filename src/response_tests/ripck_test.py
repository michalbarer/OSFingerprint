from src.response_tests.base_response_test import ResponseTest


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
        returned_ip_checksum = self.response_data.get("returned_ip_checksum")

        if ip_checksum is None or returned_ip_checksum is None:
            print("No IP checksum data available for analysis.")
            return None

        if returned_ip_checksum == 0:
            result = "Z"
        elif returned_ip_checksum == ip_checksum:
            result = "G"
        else:
            result = "I"

        print(f"Integrity of Returned Probe IP Checksum Value (RIPCK): {result}")
        return result
