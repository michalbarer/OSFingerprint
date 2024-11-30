from response_tests.base_response_test import ResponseTest


class TCPSequenceNumberTest(ResponseTest):
    """
    TCP Sequence Number (S) Test.
    Examines the 32-bit sequence number field in the TCP header and compares it
    to the acknowledgment number in the corresponding probe.
    """

    def analyze(self):
        """
        Analyzes the TCP sequence number field and determines its relationship to the acknowledgment number.
        """
        # Retrieve sequence and acknowledgment numbers from the response data
        response_sequence_number = self.response_data.get("response_sequence_number")
        probe_ack_number = self.response_data.get("probe_ack_number")

        if response_sequence_number is None or probe_ack_number is None:
            print("Insufficient data: Sequence or acknowledgment number missing.")
            return None

        # Compare sequence number to acknowledgment number
        if response_sequence_number == 0:
            result = "Z"  # Sequence number is zero
        elif response_sequence_number == probe_ack_number:
            result = "A"  # Sequence number matches acknowledgment number
        elif response_sequence_number == probe_ack_number + 1:
            result = "A+"  # Sequence number matches acknowledgment number + 1
        else:
            result = "O"  # Sequence number is something else

        print(f"TCP Sequence Number (S) Result: {result}")
        return result
