from typing import List

from response_tests.ip_id_test.base_ip_id_test import IPIDSequenceTest


class ICMPIIDII(IPIDSequenceTest):
    """
    IP ID Sequence Generation Test (II) based on ICMP responses to IE ping probes.
    Requires both ICMP responses.
    """

    def extract_ip_ids(self) -> List[int]:
        """
        Extracts IP IDs from ICMP responses to IE ping probes.
        """
        icmp_responses = self.response_data.get("responses", [])
        if len(icmp_responses) < 2:
            print("II Test: Insufficient ICMP responses (both required).")
            return []

        ip_ids = []
        for resp in icmp_responses[:2]:
            if resp and "IP" in resp:
                ip_ids.append(resp["IP"].id)
            else:
                print("II Test: Missing IP layer in an ICMP response.")
        return ip_ids
