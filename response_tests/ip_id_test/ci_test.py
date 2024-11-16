from typing import List

from response_tests.ip_id_test.base_ip_id_test import IPIDSequenceTest


class TCPIIDCI(IPIDSequenceTest):
    """
    IP ID Sequence Generation Test (CI) based on TCP probes to closed ports (T5, T6, T7).
    Requires at least two responses.
    """

    def extract_ip_ids(self) -> List[int]:
        """
        Extracts IP IDs from TCP probes sent to closed ports (T5, T6, T7).
        """
        closed_port_responses = self.response_data.get("closed_port_responses", [])
        if len(closed_port_responses) < 2:
            print("CI Test: Insufficient responses (minimum 2 required).")
            return []

        ip_ids = []
        for resp in closed_port_responses[:3]:  # T5, T6, T7
            if resp and "IP" in resp:
                ip_ids.append(resp["IP"].id)
            else:
                print("CI Test: Missing IP layer in a response.")
        return ip_ids
