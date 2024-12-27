import math

from src.response_tests.base_response_test import ResponseTest


class TCPTimestampOptionTest(ResponseTest):
    """
    Tests the TCP timestamp option to determine the target OS characteristics.
    This test calculates the timestamp increments per second and returns a value based on the average increments.
    """

    def analyze(self):
        timestamp_vals = self.response_data.get("timestamp_vals")
        timestamps = self.response_data.get("timestamps")

        if len(timestamp_vals) < 2:
            return "U"

        if any(ts == 0 for ts in timestamp_vals):
            return 0

        timestamp_rate = []
        for i in range(1, len(timestamp_vals)):
            ts_diff = timestamp_vals[i] - timestamp_vals[i - 1]
            time_diff = timestamps[i] - timestamps[i - 1]

            if time_diff > 0:
                rate = ts_diff / time_diff
                timestamp_rate.append(rate)

        avg_rate = sum(timestamp_rate) / len(timestamp_rate)

        if avg_rate <= 5.66:
            return 1
        elif 70 <= avg_rate <= 150:
            return 7
        elif 150 <= avg_rate <= 350:
            return 8
        else:
            log_rate = round(math.log2(avg_rate))
            return log_rate
