from abc import ABC, abstractmethod

class ResponseTest(ABC):
    """
    Abstract base class for response tests.
    Each test must implement its own `analyze` method.
    """
    def __init__(self, response_data):
        self.response_data = response_data

    @abstractmethod
    def analyze(self):
        """
        Analyzes the response data for a specific test.
        """
        pass
