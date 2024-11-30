from response_tests.base_response_test import ResponseTest


class TCPAcknowledgmentNumberTest(ResponseTest):
    """
    TCP Acknowledgment Number (A) Test.
    Examines the 32-bit acknowledgment number field in the TCP header and compares it
    to the sequence number in the corresponding probe.
    """

    def analyze(self):
        """
        Analyzes the TCP acknowledgment number field and determines its relationship to the sequence number.
        """
        # Retrieve acknowledgment and sequence numbers from the response data
        response_ack_number = self.response_data.get("response_ack_number")
        probe_sequence_number = self.response_data.get("probe_sequence_number")

        if response_ack_number is None or probe_sequence_number is None:
            print("Insufficient data: Acknowledgment or sequence number missing.")
            return None

        if response_ack_number == 0:
            result = "Z"
        elif response_ack_number == probe_sequence_number:
            result = "S"
        elif response_ack_number == probe_sequence_number + 1:
            result = "S+"
        else:
            result = "O"

        print(f"TCP Acknowledgment Number (A) Result: {result}")
        return result
