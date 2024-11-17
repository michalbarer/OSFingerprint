import math

from response_tests.base_response_test import ResponseTest


class TCPISNRateTest(ResponseTest):
    """
    TCP ISN Counter Rate (ISR) Test.
    """
    def __init__(self, response_data):
        super().__init__(response_data)
        self.max_isn_value = 2 ** 32

    def analyze(self):
        # Retrieve ISNs and timestamps from the response data
        isns = self.response_data.get("isns")
        timestamps = self.response_data.get("timestamps")

        # Check if we have enough data to analyze
        if not isns or not timestamps or len(isns) < 2 or len(timestamps) < 2:
            print("Insufficient data to analyze ISN rate.")
            return 0

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

        # Step 3: Compute the average of seq_rates
        if not seq_rates:
            print("No valid rates calculated.")
            return 0
        average_rate = sum(seq_rates) / len(seq_rates)

        # Step 4: Calculate ISR based on average rate
        if average_rate < 1:
            isr = 0
        else:
            isr = round(8 * math.log2(average_rate))

        print(f"TCP ISN Counter Rate (ISR): {isr}")
        return hex(isr)
