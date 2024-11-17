from math import gcd
from functools import reduce

from response_tests.base_response_test import ResponseTest


class TCPISNGCDTest(ResponseTest):
    """
    TCP ISN Greatest Common Divisor (GCD) Test.
    """
    def __init__(self, response_data):
        super().__init__(response_data)
        self.max_isn_value = 2 ** 32

    def analyze(self):
        # Retrieve ISNs from the response data
        isns = self.response_data.get("isns")

        if not isns or len(isns) < 2:
            print("Insufficient ISNs to analyze GCD")
            return None

        # Step 1: Calculate diff1 array, handling wraparound
        diff1 = []
        for i in range(1, len(isns)):
            # Calculate the difference between consecutive ISNs
            isn_diff = isns[i] - isns[i - 1]

            # Handle wraparound
            if isn_diff < 0:
                # Calculate the wraparound difference "up" and "down"
                diff_up = isn_diff + self.max_isn_value
                diff_down = -isn_diff
                # Take the smaller absolute difference
                isn_diff = min(diff_up, diff_down)

            diff1.append(abs(isn_diff))

        if not diff1:
            print("No differences calculated, unable to determine GCD")
            return None

        # Step 2: Calculate the GCD of all differences in diff1
        gcd_result = reduce(gcd, diff1)

        print(f"GCD of TCP ISN increments: {gcd_result}")
        return hex(gcd_result)
