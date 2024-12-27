from math import gcd
from functools import reduce

from src.response_tests.base_response_test import ResponseTest


class TCPISNGCDTest(ResponseTest):
    """
    TCP ISN Greatest Common Divisor (GCD) Test.
    """
    def __init__(self, response_data):
        super().__init__(response_data)
        self.max_isn_value = 2 ** 32

    def analyze(self):
        isns = self.response_data.get("isns")

        if not isns or len(isns) < 2:
            return None

        diff1 = []
        for i in range(1, len(isns)):
            isn_diff = isns[i] - isns[i - 1]
            if isn_diff < 0:
                diff_up = isn_diff + self.max_isn_value
                diff_down = -isn_diff
                isn_diff = min(diff_up, diff_down)

            diff1.append(abs(isn_diff))

        if not diff1:
            return None

        gcd_result = reduce(gcd, diff1)
        return gcd_result
