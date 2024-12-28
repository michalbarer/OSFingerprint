from typing import List

from src.response_tests.ip_id_test.base_ip_id_test import IPIDSequenceTest


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

        if len(closed_port_ipd_ids) < 2:
            return []

        return closed_port_ipd_ids
