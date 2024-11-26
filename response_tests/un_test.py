import sys

from response_tests.base_response_test import ResponseTest


class UnusedPortUnreachableFieldTest(ResponseTest):
    """
    Unused Port Unreachable Field Nonzero (UN) Test.
    Records the value of the last four bytes of an ICMP port unreachable message header.
    If these bytes are nonzero, the value is recorded; otherwise, it is zero.
    """

    def analyze(self):
        """
        Analyzes the last four bytes of the ICMP port unreachable message header.
        """
        # Retrieve the last four bytes of the ICMP message header from the response data
        unused_field = self.response_data.get("unused_field")

        if unused_field is None:
            print("No unused field data available for analysis.")
            return None

        print(f"Unused Port Unreachable Field (UN): {unused_field}")
        if unused_field == b'':
            return 0
        else:
            return int.from_bytes(unused_field, sys.byteorder)
