from response_tests.base_response_test import ResponseTest

class TCPAndICMPIPIDSequenceBooleanTest(ResponseTest):
    """
    Tests whether the IP ID sequence is shared between TCP and ICMP responses.
    This test is performed if the II test is RI, BI, or I, and the TI test indicates the same sequence.
    """

    def __init__(self, icmp_response_data, tcp_response_data, ii_result, ti_result):
        """
        :param icmp_response_data: Data from ICMP probes.
        :param tcp_response_data: Data from TCP probes.
        :param ii_result: Result of the II test (ICMP IP ID sequence analysis).
        :param ti_result: Result of the TI test (TCP IP ID sequence analysis).
        """
        super().__init__(icmp_response_data)
        self.response_data = {
            "tcp_ip_ids": tcp_response_data.get("ip_ids", []),
            "icmp_ip_ids": icmp_response_data.get("ip_ids", [])
        }
        self.ii_result = ii_result
        self.ti_result = ti_result

    def analyze(self):
        # Ensure conditions for SS test are met
        if self.ii_result not in {"RI", "BI", "I"}:
            print("SS test not performed: II test result is not RI, BI, or I")
            return None

        if self.ii_result != self.ti_result:
            print("SS test not performed: TI result does not match II result")
            return None

        tcp_ip_ids = self.response_data.get("tcp_ip_ids")
        icmp_ip_ids = self.response_data.get("icmp_ip_ids")

        if len(tcp_ip_ids) < 2 or len(icmp_ip_ids) < 2:
            print("Insufficient data for SS test")
            return None

        # Calculate average increment (avg) for TCP IP IDs
        tcp_id_diff = tcp_ip_ids[-1] - tcp_ip_ids[0]
        tcp_avg = tcp_id_diff / (len(tcp_ip_ids) - 1)

        # Check the condition for shared sequence
        first_icmp_id = icmp_ip_ids[0]
        last_tcp_id = tcp_ip_ids[-1]

        if first_icmp_id < (last_tcp_id + 3 * tcp_avg):
            print("SS test result: S (Shared)")
            return "S"
        else:
            print("SS test result: O (Other)")
            return "O"
