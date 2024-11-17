import math
import statistics
from response_tests.base_response_test import ResponseTest


class TCPISNSequencePredictabilityTest(ResponseTest):
    """
    TCP ISN Sequence Predictability Index (SP) Test.
    """

    def __init__(self, response_data, gcd_value):
        super().__init__(response_data)
        self.gcd_value = gcd_value
        self.max_isn_value = 2 ** 32

    def analyze(self):
        # Retrieve ISNs and timestamps from the response data
        isns = self.response_data.get("isns")
        timestamps = self.response_data.get("timestamps")

        if not isns or len(isns) < 4:
            print("Insufficient ISNs to analyze SP (minimum 4 responses required).")
            return None

        if not timestamps or len(timestamps) != len(isns):
            print("Timestamps do not match ISNs. SP cannot be calculated.")
            return None

        # Step 1: Calculate ISN differences, handling wraparound, and store in diff1
        diff1 = []
        for i in range(1, len(isns)):
            isn_diff = isns[i] - isns[i - 1]
            # If the difference is negative, assume wraparound and adjust
            if isn_diff < 0:
                isn_diff += self.max_isn_value
            diff1.append(isn_diff)

        # Step 2: Calculate seq_rates by dividing each ISN difference by the time difference
        seq_rates = []
        for i in range(1, len(timestamps)):
            time_diff = timestamps[i] - timestamps[i - 1]
            if time_diff > 0:
                rate = diff1[i - 1] / time_diff
                seq_rates.append(rate)
            else:
                print("Warning: Time difference is zero or negative, skipping this pair.")

        # Step 3: Divide seq_rates by GCD if GCD > 9
        if self.gcd_value > 9:
            seq_rates = [rate / self.gcd_value for rate in seq_rates]

        # Step 4: Calculate the standard deviation of the adjusted seq_rates
        try:
            std_dev = statistics.stdev(seq_rates)
        except statistics.StatisticsError:
            print("Standard deviation could not be calculated (insufficient data).")
            return None

        # Step 5: Compute SP based on the standard deviation
        if std_dev <= 1:
            sp = 0
        else:
            sp = round(8 * math.log2(std_dev))

        print(f"TCP ISN Sequence Predictability Index (SP): {sp}")
        return hex(sp)
