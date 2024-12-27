from response_tests.base_response_test import ResponseTest


class ICMPDontFragmentTest(ResponseTest):
    """
    Compares the 'Don't Fragment' (DF) bit between two ICMP echo responses.
    """

    def analyze(self):
        icmp_responses = self.response_data.get("icmp_responses")
        if not icmp_responses or len(icmp_responses) != 2:
            print("Insufficient ICMP responses for DFT analysis.")
            return None

        df_bit1 = icmp_responses[0].get("df", False)
        df_bit2 = icmp_responses[1].get("df", False)

        if not df_bit1 and not df_bit2:
            result = "N"
        elif df_bit1 == df_bit2:
            result = "S"
        elif df_bit1 and df_bit2:
            result = "Y"
        else:
            result = "O"

        print(f"DFI Result: {result}")
        return result
