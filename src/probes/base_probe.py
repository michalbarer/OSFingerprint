from abc import ABC, abstractmethod


class Probe(ABC):
    """
    Abstract base class for network probes.
    """

    def __init__(self, target_ip, target_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.response = None

    @abstractmethod
    def send_probe(self):
        """
        Sends the probe and stores the response.
        """
        pass

    @abstractmethod
    def get_response_data(self):
        """
        Returns a dictionary of probe's response data
        """
        pass
