from typing import List

from response_tests.ip_id_test.base_ip_id_test import IPIDSequenceTest


class TCPIIDTI(IPIDSequenceTest):
    """
    IP ID Sequence Generation Test (TI) based on TCP SEQ probe responses.
    Requires at least three responses.
    """

    def extract_ip_ids(self) -> List[int]:
        """
        Extracts IP IDs from TCP SEQ probe responses.
        """
        ip_ids = self.response_data.get("ip_ids", [])
        ip_ids = [ip_id for ip_id in ip_ids if ip_id is not None]

        if len(ip_ids) < 3:
            print("TI Test: Insufficient responses (minimum 3 required).")
            return []

        return ip_ids
