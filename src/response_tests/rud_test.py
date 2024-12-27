from src.response_tests.base_response_test import ResponseTest


class IntegrityReturnedUDPDataTest(ResponseTest):
    """
    Integrity of Returned UDP Data (RUD) Test.
    Checks the integrity of the returned UDP payload.
    - G: All bytes match the expected value (0x43) or payload is truncated to zero length.
    - I (Invalid): Payload does not match the expected value.
    """

    def analyze(self):
        """
        Analyzes the returned UDP payload data for integrity.
        """
        udp_payload = self.response_data.get("udp_payload")

        if udp_payload is None:
            print("No UDP payload data available for analysis.")
            return "I"

        if all(byte == 0x43 for byte in udp_payload.load) or len(udp_payload) == 0:
            result = "G"
        else:
            result = "I"

        print(f"Integrity of Returned UDP Data (RUD): {result}")
        return result
