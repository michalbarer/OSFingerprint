import math

from response_tests.base_response_test import ResponseTest


class TCPTimestampOptionTest(ResponseTest):
    """
    Tests the TCP timestamp option to determine the target OS characteristics.
    This test calculates the timestamp increments per second and returns a value based on the average increments.
    """

    def analyze(self):
        # Retrieve timestamp values (TSval) and the time elapsed between probes
        timestamp_vals = self.response_data.get("timestamp_vals")  # List of TSval values from responses
        timestamps = self.response_data.get("timestamps")  # List of timestamps for each probe

        if len(timestamp_vals) < 2:
            print("Insufficient data for TS test")
            return "U"  # Unsupported if we don't have at least 2 responses with TSvals

        if any(ts == 0 for ts in timestamp_vals):
            print("TS test result: 0 (Zero timestamp)")
            return 0

        # Step 1: Calculate the rate of timestamp increments per second
        timestamp_rate = []
        for i in range(1, len(timestamp_vals)):
            ts_diff = timestamp_vals[i] - timestamp_vals[i - 1]
            time_diff = timestamps[i] - timestamps[i - 1]

            # Ensure no division by zero and avoid negative rates
            if time_diff > 0:
                rate = ts_diff / time_diff
                timestamp_rate.append(rate)

        # Step 2: Calculate the average increment rate
        avg_rate = sum(timestamp_rate) / len(timestamp_rate)

        # Step 3: Apply the specific range logic
        if avg_rate <= 5.66:
            print("TS test result: 1 (Frequency: 2 Hz)")
            return 1  # Common for OSes with 2 Hz timestamp
        elif 70 <= avg_rate <= 150:
            print("TS test result: 7 (Frequency: 100 Hz)")
            return 7  # Common for OSes with 100 Hz timestamp
        elif 150 <= avg_rate <= 350:
            print("TS test result: 8 (Frequency: 200 Hz)")
            return 8  # Common for OSes with 200 Hz timestamp
        else:
            # If the rate doesn't fall into the predefined ranges, calculate log base-2 of the average rate
            log_rate = round(math.log2(avg_rate))
            print(f"TS test result: {log_rate} (Logarithmic calculation of average rate)")
            return log_rate  # Return log of rate if it's outside the predefined ranges
