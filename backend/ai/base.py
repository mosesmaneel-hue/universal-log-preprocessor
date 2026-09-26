"""
Base AI Provider Interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any


class AIProvider(ABC):
    """Abstract base class for all AI provider implementations."""

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Returns provider status metadata safely without revealing secrets.
        Expected keys: configured (bool), available (bool), provider (str), model (str), message (str)
        """
        pass

    @abstractmethod
    def generate(self, prompt: str, system_context: str) -> Dict[str, Any]:
        """
        Executes generation against provider.
        Returns:
            {
                "status": "success" | "error",
                "configured": bool,
                "model": str,
                "response": str,
                "error_code": Optional[str]
            }
        """
        pass
