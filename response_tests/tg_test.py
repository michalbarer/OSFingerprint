from response_tests.base_response_test import ResponseTest


class IPInitialTTLGuessTest(ResponseTest):
    """
    IP Initial Time-to-Live Guess (TG) Test.
    Makes an educated guess about the initial TTL value when no response is received.
    """

    def analyze(self):
        """
        Analyzes the response data and guesses the initial TTL value.
        """
        # Retrieve the observed TTL from the response, if available
        observed_ttl = self.response_data.get("observed_ttl")

        # If no TTL is observed, the guess is undefined
        if observed_ttl is None:
            print("No observed TTL available, unable to guess initial TTL.")
            return None

        # Define common initial TTL values used by systems
        common_ttl_values = [32, 64, 128, 255]

        # Round the observed TTL up to the next common value
        for ttl in common_ttl_values:
            if observed_ttl <= ttl:
                print(f"Guessed Initial TTL (TG): {ttl}")
                return ttl

        # If no match is found, return the maximum common TTL (255)
        print("Guessed Initial TTL (TG): 255")
        return 255
