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
        ack_number = self.response_data.get("ack_number")
        sequence_number = self.response_data.get("sequence_number")

        if ack_number is None or sequence_number is None:
            print("Insufficient data: Acknowledgment or sequence number missing.")
            return None

        # Compare acknowledgment number to sequence number
        if ack_number == 0:
            result = "Z"  # Acknowledgment number is zero
        elif ack_number == sequence_number:
            result = "S"  # Acknowledgment number matches sequence number
        elif ack_number == sequence_number + 1:
            result = "S+"  # Acknowledgment number matches sequence number + 1
        else:
            result = "O"  # Acknowledgment number is something else

        print(f"TCP Acknowledgment Number (A) Result: {result}")
        return result