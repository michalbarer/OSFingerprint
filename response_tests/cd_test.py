from response_tests.base_response_test import ResponseTest


class ICMPResponseCodeTest(ResponseTest):
    """
    ICMP Response Code (CD) Test.
    Analyzes the code values of ICMP echo replies for two probes and combines
    them into a single CD value as described in Table 8.7.
    """

    def analyze(self):
        """
        Analyzes the ICMP response codes and computes the CD value.
        """
        icmp_responses = self.response_data.get("icmp_responses", [])

        if len(icmp_responses) < 2:
            print("Insufficient ICMP responses available for analysis.")
            return None

        # Extract the codes and probe configuration
        response_code_1 = icmp_responses[0].get("response_code") if icmp_responses[0] else None
        response_code_2 = icmp_responses[1].get("response_code") if icmp_responses[1] else None
        probe_code_1 = icmp_responses[0].get("probe_code") if icmp_responses[0] else None
        probe_code_2 = icmp_responses[1].get("probe_code") if icmp_responses[1] else None

        if response_code_1 is None or response_code_2 is None:
            print("Insufficient ICMP response code data available for analysis.")
            return None

        # Determine the CD value based on Table 8.7
        if response_code_1 == 0 and response_code_2 == 0:
            result = "Z"  # Both code values are zero
        elif response_code_1 == probe_code_1 and response_code_2 == probe_code_2:
            result = "S"  # Both codes match their respective probe codes
        elif response_code_1 == response_code_2 and response_code_1 != 0:
            result = f"{response_code_1}"  # Both codes are the same non-zero value
        else:
            result = "O"  # Any other combination

        print(f"ICMP Response Code (CD) Value: {result}")
        return result
