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
        # Retrieve the ICMP response codes and probe codes from the response data
        response_code_1 = self.response_data.get("response_code_1")
        response_code_2 = self.response_data.get("response_code_2")
        probe_code_1 = self.response_data.get("probe_code_1")
        probe_code_2 = self.response_data.get("probe_code_2")

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
