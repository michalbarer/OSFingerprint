from abc import abstractmethod
from typing import List, Optional

from response_tests.base_response_test import ResponseTest

# todo: check why my implementation is different (stash)
def classify_ipid_sequence(ip_ids: List[int]) -> Optional[str]:
    """
    Classifies the IP ID sequence based on the differences between consecutive IDs.
    """
    if not ip_ids:
        return None

    if all(id == 0 for id in ip_ids):
        return 'Z'

    diffs = []
    for i in range(1, len(ip_ids)):
        diff = (ip_ids[i] - ip_ids[i - 1]) % 65536  # 16-bit wraparound
        diffs.append(diff)

    if any(diff >= 20000 for diff in diffs):
        return 'RD'

    if all(id == ip_ids[0] for id in ip_ids):
        return hex(ip_ids[0])

    # Check for RI: any diff >1000 and not divisible by 256
    if any(diff > 1000 and diff % 256 != 0 for diff in diffs):
        return 'RI'

    # Check for BI: all diffs divisible by 256 and <=5120
    if all(diff % 256 == 0 and diff <= 5120 for diff in diffs):
        return 'BI'

    # Check for I: all diffs <10
    if all(diff < 10 for diff in diffs):
        return 'I'

    return None


class IPIDSequenceTest(ResponseTest):
    """
    Abstract base class for IP ID Sequence Tests (TI, CI, II).
    """

    @abstractmethod
    def extract_ip_ids(self) -> List[int]:
        """
        Extracts IP IDs from the response data.
        """
        pass

    def analyze(self) -> Optional[str]:
        ip_ids = self.extract_ip_ids()

        if not ip_ids:
            print(f"{self.__class__.__name__}: No IP IDs extracted.")
            return None

        classification = classify_ipid_sequence(ip_ids)
        if classification:
            print(f"{self.__class__.__name__}: IP ID Sequence Classification: {classification}")
        else:
            print(f"{self.__class__.__name__}: IP ID Sequence could not be classified.")
        return classification
