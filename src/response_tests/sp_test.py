import math
import statistics
from src.response_tests.base_response_test import ResponseTest


class TCPISNSequencePredictabilityTest(ResponseTest):
    """
    TCP ISN Sequence Predictability Index (SP) Test.
    """

    def __init__(self, response_data, gcd_value):
        super().__init__(response_data)
        self.gcd_value = gcd_value
        self.max_isn_value = 2 ** 32

    def analyze(self):
        isns = self.response_data.get("isns")
        timestamps = self.response_data.get("timestamps")

        if not isns or len(isns) < 4:
            return None

        if not timestamps or len(timestamps) != len(isns):
            return None

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

        if self.gcd_value > 9:
            seq_rates = [rate / self.gcd_value for rate in seq_rates]

        # Calculate the standard deviation of the adjusted seq_rates
        try:
            std_dev = statistics.stdev(seq_rates)
        except statistics.StatisticsError:
            return None

        if std_dev <= 1:
            sp = 0
        else:
            sp = round(8 * math.log2(std_dev))

        return sp
