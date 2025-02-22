import sys

from src.response_tests.base_response_test import ResponseTest


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
        unused_field = self.response_data.get("unused_field")

        if unused_field is None:
            return None

        if unused_field == b'':
            return 0
        else:
            return int.from_bytes(unused_field, sys.byteorder)
