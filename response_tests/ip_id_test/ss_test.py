from response_tests.base_response_test import ResponseTest

# todo: check why my implementation is different (stash)
class TCPAndICMPIPIDSequenceBooleanTest(ResponseTest):
    """
    Tests whether the IP ID sequence is shared between TCP and ICMP responses.
    This test is performed if the II test is RI, BI, or I, and the TI test indicates the same sequence.
    """

    def analyze(self):
        tcp_ip_ids = self.response_data.get("tcp_ip_ids")
        icmp_ip_ids = self.response_data.get("icmp_ip_ids")

        if len(tcp_ip_ids) < 2 or len(icmp_ip_ids) < 2:
            print("Insufficient data for SS test")
            return None

        tcp_id_diff = tcp_ip_ids[-1] - tcp_ip_ids[0]
        tcp_avg = tcp_id_diff / (len(tcp_ip_ids) - 1)

        # Check the condition for SS test
        first_icmp_id = icmp_ip_ids[0]
        last_tcp_id = tcp_ip_ids[-1]

        if first_icmp_id < (last_tcp_id + 3 * tcp_avg):
            print("SS test result: S (Shared)")
            return "S"  # Shared sequence
        else:
            print("SS test result: O (Other)")
            return "O"  # Different sequences
