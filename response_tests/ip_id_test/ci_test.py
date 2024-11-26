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
        closed_port_ipd_ids = self.response_data.get("closed_port_ipd_ids", [])
        closed_port_ipd_ids = [ip_id for ip_id in closed_port_ipd_ids if ip_id is not None]

        if len(closed_port_ipd_ids) < 2:
            print("CI Test: Insufficient responses (minimum 2 required).") # todo: is 2 responses or 2 ip ids? e.g - 2 responses and 1 ip id
            return []

        return closed_port_ipd_ids
