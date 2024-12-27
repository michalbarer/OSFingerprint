from response_tests.base_response_test import ResponseTest


class ReturnedProbeIPIDValueTest(ResponseTest):
    """
    Returned Probe IP ID Value (RID) Test.
    The U1 probe uses a static IP ID value of 0x1042. If this value is returned in the
    ICMP port unreachable message, 'G' is stored. Otherwise, the exact value is stored.
    Some systems may flip the bytes and return 0x4210.
    """

    def analyze(self):
        """
        Analyzes the returned IP ID value from the ICMP response.
        """
        returned_ip_id = self.response_data.get("returned_ip_id")

        if returned_ip_id is None:
            print("No returned IP ID data available for analysis.")
            return None

        if returned_ip_id == 1042:
            print("Returned Probe IP ID Value (RID): G")
            return "G"

        if returned_ip_id == 4210:
            print(f"Returned Probe IP ID Value (RID): 0x4210 (flipped bytes)")
            return int(0x4210)

        print(f"Returned Probe IP ID Value (RID): {returned_ip_id}")
        return returned_ip_id
