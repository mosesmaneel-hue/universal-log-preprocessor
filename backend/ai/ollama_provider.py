"""
Ollama Local Development Provider.
Connects to local Ollama instance (default: Qwen3 on http://127.0.0.1:11434).
"""
import os
import json
import urllib.request
from typing import Dict, Any
from ai.base import AIProvider


class OllamaProvider(AIProvider):
    def __init__(self, endpoint: str = None, model: str = None, timeout: int = None):
        self.endpoint = (endpoint or os.getenv("OLLAMA_ENDPOINT", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("AI_MODEL", "qwen3")
        try:
            self.timeout = int(timeout or os.getenv("AI_REQUEST_TIMEOUT_SECONDS", 75))
        except (ValueError, TypeError):
            self.timeout = 75

    def get_status(self) -> Dict[str, Any]:
        tags_url = f"{self.endpoint}/api/tags"
        is_available = False
        models = []

        try:
            req = urllib.request.Request(tags_url, headers={"User-Agent": "ARC-Backend/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    is_available = True
                    models = [m.get("name") for m in data.get("models", [])]
        except Exception:
            is_available = False

        has_target_model = any(self.model.lower() in m.lower() for m in models) if is_available else False

        return {
            "status": "success",
            "configured": is_available,
            "provider": "ollama",
            "available": is_available,
            "ollama_available": is_available,
            "target_model": self.model,
            "target_model_available": has_target_model,
            "installed_models": models,
            "endpoint": self.endpoint,
            "model": self.model,
            "byok_supported": True,
            "message": (
                f"Ollama is online with model '{self.model}'."
                if is_available
                else f"Ollama is not running locally at {self.endpoint}. To enable AI Assistant: 1) Install Ollama (https://ollama.com), 2) Run 'ollama run {self.model}'."
            )
        }

    def generate(self, prompt: str, system_context: str) -> Dict[str, Any]:
        status = self.get_status()
        if not status["available"]:
            return {
                "status": "error",
                "error_code": "AI_SERVICE_NOT_CONFIGURED",
                "configured": False,
                "model": self.model,
                "response": (
                    "⚠️ **AI Service Not Configured**\n\n"
                    f"The AI assistant is configured to run via a local Ollama instance with **{self.model}**.\n\n"
                    f"**Current Status:** Ollama is not detected at `{self.endpoint}`.\n\n"
                    "**How to Enable:**\n"
                    "1. Download & install Ollama: [https://ollama.com](https://ollama.com)\n"
                    f"2. Open your terminal and pull the model:\n"
                    f"   ```bash\n"
                    f"   ollama run {self.model}\n"
                    "   ```\n"
                    "3. Once running, refresh this page to begin chatting."
                )
            }

        # Determine model name to send
        selected_model = self.model if status["target_model_available"] else (status["installed_models"][0] if status["installed_models"] else self.model)

        payload = {
            "model": selected_model,
            "prompt": prompt,
            "system": system_context,
            "stream": False
        }

        try:
            req = urllib.request.Request(
                f"{self.endpoint}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "ARC-Backend/1.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "status": "success",
                    "configured": True,
                    "model": selected_model,
                    "response": data.get("response", "").strip()
                }
        except Exception as e:
            return {
                "status": "error",
                "error_code": "OLLAMA_QUERY_FAILED",
                "configured": True,
                "model": selected_model,
                "response": f"Failed to get response from local Ollama model: {str(e)}"
            }
