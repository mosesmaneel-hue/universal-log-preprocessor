"""
Standard REST API AI Provider.
Supports Platform AI (server-side environment credentials) and BYOK (request-scoped credentials).
Implements safe error redaction, safe status checks, and OpenAI-compatible completions.
"""
import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from ai.base import AIProvider


def redact_secrets(text: str, secret: Optional[str]) -> str:
    """Safely redact secret tokens from any message or traceback."""
    if not text:
        return ""
    clean = str(text)
    if secret and len(secret) >= 4:
        clean = clean.replace(secret, "[REDACTED]")
    return clean


def normalize_chat_endpoint(endpoint: Optional[str]) -> str:
    """
    Normalizes an OpenAI-compatible API base endpoint so that it points to /chat/completions.
    Avoids duplicate path segments and handles endpoints with or without trailing slashes.
    Example:
      https://generativelanguage.googleapis.com/v1beta/openai/ -> https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
      https://api.openai.com/v1 -> https://api.openai.com/v1/chat/completions
    """
    raw = (endpoint or "").strip()
    if not raw:
        return "https://api.openai.com/v1/chat/completions"
    
    clean = raw.rstrip("/")
    if clean.endswith("/chat/completions"):
        return clean
    if clean.endswith("/chat"):
        return f"{clean}/completions"
    return f"{clean}/chat/completions"


class APIProvider(AIProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        provider_name: str = "api"
    ):
        # Resolve credentials safely without logging
        self._api_key = (api_key or os.getenv("AI_API_KEY") or "").strip()
        
        # Endpoint resolution: normalize to standard /chat/completions endpoint
        raw_endpoint = endpoint or os.getenv("AI_API_ENDPOINT")
        self.endpoint = normalize_chat_endpoint(raw_endpoint)

        self.model = (model or os.getenv("AI_MODEL") or "gpt-4o-mini").strip()
        self.provider_name = provider_name

        try:
            self.timeout = int(timeout or os.getenv("AI_REQUEST_TIMEOUT_SECONDS", 75))
        except (ValueError, TypeError):
            self.timeout = 75

    def get_status(self) -> Dict[str, Any]:
        """Safely report status without revealing the secret key or Authorization headers."""
        is_configured = bool(self._api_key)
        
        # Safe display endpoint (only hostname + path, no credentials)
        display_endpoint = ""
        try:
            p = urlparse(self.endpoint)
            display_endpoint = f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            display_endpoint = "configured-endpoint"

        return {
            "status": "success",
            "configured": is_configured,
            "provider": self.provider_name,
            "available": is_configured,
            "model": self.model,
            "endpoint": display_endpoint,
            "byok_supported": True,
            "message": (
                f"Platform AI is connected using model '{self.model}'."
                if is_configured
                else "Platform AI key is not configured on the server."
            )
        }

    def generate(self, prompt: str, system_context: str) -> Dict[str, Any]:
        """Send chat generation request to configured AI API endpoint."""
        if not self._api_key:
            return {
                "status": "error",
                "error_code": "MISSING_API_KEY",
                "configured": False,
                "model": self.model,
                "response": "AI API key is missing. Please configure AI_API_KEY in server environment or provide a key."
            }

        # Build standard chat completions payload
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_context},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
            "User-Agent": "ARC-AI-Telemetry/1.0"
        }

        try:
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.status
                data = json.loads(resp.read().decode("utf-8"))
                
                # Standard OpenAI-style response: data["choices"][0]["message"]["content"]
                choices = data.get("choices", [])
                if choices and isinstance(choices, list):
                    msg = choices[0].get("message", {})
                    content = msg.get("content", "")
                    return {
                        "status": "success",
                        "configured": True,
                        "model": self.model,
                        "response": content.strip()
                    }
                
                # Direct response fallback (e.g. some custom providers)
                if "response" in data:
                    return {
                        "status": "success",
                        "configured": True,
                        "model": self.model,
                        "response": str(data["response"]).strip()
                    }

                return {
                    "status": "error",
                    "error_code": "MALFORMED_RESPONSE",
                    "configured": True,
                    "model": self.model,
                    "response": "Received unexpected response structure from AI provider."
                }

        except urllib.error.HTTPError as e:
            code = e.code
            if code in (401, 403):
                return {
                    "status": "error",
                    "error_code": "AUTHENTICATION_FAILED",
                    "configured": True,
                    "model": self.model,
                    "response": "Authentication failed with AI provider. Please verify credentials."
                }
            elif code == 429:
                return {
                    "status": "error",
                    "error_code": "RATE_LIMITED",
                    "configured": True,
                    "model": self.model,
                    "response": "AI provider rate limit reached. Please retry in a few moments."
                }
            elif code >= 500:
                return {
                    "status": "error",
                    "error_code": "PROVIDER_UNAVAILABLE",
                    "configured": True,
                    "model": self.model,
                    "response": f"AI service temporarily unavailable (HTTP {code})."
                }
            else:
                return {
                    "status": "error",
                    "error_code": f"HTTP_{code}",
                    "configured": True,
                    "model": self.model,
                    "response": f"AI provider returned error HTTP {code}."
                }

        except urllib.error.URLError as e:
            reason_str = redact_secrets(str(e.reason), self._api_key)
            if "timed out" in reason_str.lower():
                return {
                    "status": "error",
                    "error_code": "TIMEOUT",
                    "configured": True,
                    "model": self.model,
                    "response": f"AI request timed out after {self.timeout} seconds."
                }
            return {
                "status": "error",
                "error_code": "PROVIDER_UNAVAILABLE",
                "configured": True,
                "model": self.model,
                "response": "Could not connect to AI provider endpoint."
            }

        except Exception as e:
            safe_err = redact_secrets(str(e), self._api_key)
            return {
                "status": "error",
                "error_code": "REQUEST_FAILED",
                "configured": True,
                "model": self.model,
                "response": f"AI query encountered an error: {safe_err}"
            }
