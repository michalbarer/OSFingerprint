import math

from src.response_tests.base_response_test import ResponseTest


class TCPISNRateTest(ResponseTest):
    """
    TCP ISN Counter Rate (ISR) Test.
    """
    def __init__(self, response_data):
        super().__init__(response_data)
        self.max_isn_value = 2 ** 32

    def analyze(self):
        isns = self.response_data.get("isns")
        timestamps = self.response_data.get("timestamps")

        if not isns or not timestamps or len(isns) < 2 or len(timestamps) < 2:
            return 0

        # Calculate ISN differences
        diff1 = []
        for i in range(1, len(isns)):
            isn_diff = isns[i] - isns[i - 1]
            if isn_diff < 0:
                isn_diff += self.max_isn_value
            diff1.append(isn_diff)

        # Calculate seq_rates
        seq_rates = []
        for i in range(1, len(timestamps)):
            time_diff = timestamps[i] - timestamps[i - 1]
            if time_diff > 0:
                rate = diff1[i - 1] / time_diff
                seq_rates.append(rate)

        if not seq_rates:
            return 0
        average_rate = sum(seq_rates) / len(seq_rates)

        if average_rate < 1:
            isr = 0
        else:
            isr = round(8 * math.log2(average_rate))

        return isr
