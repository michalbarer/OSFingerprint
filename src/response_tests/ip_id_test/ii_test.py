from typing import List

from src.response_tests.ip_id_test.base_ip_id_test import IPIDSequenceTest


class ICMPIIDII(IPIDSequenceTest):
    """
    IP ID Sequence Generation Test (II) based on ICMP responses to IE ping probes.
    Requires both ICMP responses.
    """

    def extract_ip_ids(self) -> List[int]:
        """
        Extracts IP IDs from ICMP responses to IE ping probes.
        """
        icmp_ip_ids = self.response_data.get("ip_ids", [])

        if len(icmp_ip_ids) < 2:
            print("II Test: Insufficient ICMP responses (both required).")
            return []

        return icmp_ip_ids
