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
        responses = self.response_data.get("responses", [])
        if len(responses) < 3:
            print("TI Test: Insufficient responses (minimum 3 required).")
            return []

        ip_ids = []
        for resp in responses[:3]:
            if resp and "IP" in resp:
                ip_ids.append(resp["IP"].id)
            else:
                print("TI Test: Missing IP layer in a response.")
        return ip_ids
