from abc import ABC, abstractmethod


class BaseParser(ABC):

    @abstractmethod
    def parse(self, raw_log: str) -> dict:
        pass

    @abstractmethod
    def name(self) -> str:
        pass