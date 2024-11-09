from math import gcd
from functools import reduce

from response_tests.base_response_test import ResponseTest


class TCPISNGCDTest(ResponseTest):
    """
    TCP ISN Greatest Common Divisor (GCD) Test.
    """

    def analyze(self):
        # Retrieve ISNs from the response data
        isns = self.response_data.get("isns")

        if not isns or len(isns) < 2:
            print("Insufficient ISNs to analyze GCD")
            return None

        # Calculate the differences between consecutive ISNs
        differences = [abs(isns[i] - isns[i - 1]) for i in range(1, len(isns))]

        if not differences:
            print("No differences calculated, unable to determine GCD")
            return None

        # Calculate the GCD of all differences
        gcd_result = reduce(gcd, differences)

        print(f"GCD of TCP ISN increments: {gcd_result}")
        return gcd_result
