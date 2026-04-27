# utils/llm_client.py
import json
import os
import threading
import time
from typing import Optional

import requests

from utils.structured_logging import get_logger, log_event


LOGGER = get_logger("vuldetection.llm_client")


class LLMClient:
    """Minimal chat-completion client with transparent error state."""

    def __init__(
        self,
        model_name: str = "deepseek-v4-pro",
        base_url: str = "https://api.deepseek.com",
        api_key: Optional[str] = None,
        max_retries: int = 2,
        retry_backoff_sec: float = 0.8,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.model_name = model_name
        self._thread_local = threading.local()
        self.last_error = ""
        self.max_retries = max(0, int(max_retries))
        self.retry_backoff_sec = max(0.0, float(retry_backoff_sec))

        if api_key is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                self.api_key = config.get("deepseek_api_key", "")
            else:
                self.api_key = ""
        else:
            self.api_key = api_key

    def _set_last_error(self, value: str) -> None:
        text = str(value or "")
        self._thread_local.last_error = text
        # Keep compatibility for existing call sites reading client.last_error directly.
        self.last_error = text

    def get_last_error(self) -> str:
        return str(getattr(self._thread_local, "last_error", self.last_error) or "")

    @staticmethod
    def _is_retryable_status(status_code: int) -> bool:
        return status_code in {408, 409, 425, 429, 500, 502, 503, 504}

    @staticmethod
    def _is_non_retryable_connection_error(exc: Exception) -> bool:
        text = str(exc or "").lower()
        hard_fail_markers = {
            "winerror 10013",
            "e_accessdenied",
            "permission denied",
            "access is denied",
            "access was denied",
            "forbidden by its access permissions",
        }
        return any(marker in text for marker in hard_fail_markers)

    @staticmethod
    def _to_safe_console_text(value: str) -> str:
        # Keep terminal output ASCII-safe to avoid locale encoding crashes.
        return str(value or "").encode("ascii", "backslashreplace").decode("ascii")

    def _log_client_error(self, event: str, attempt: int, total_attempts: int) -> None:
        log_event(
            LOGGER,
            event,
            model=self.model_name,
            base_url=self.base_url,
            attempt=attempt,
            total_attempts=total_attempts,
            error=self._to_safe_console_text(self.get_last_error()),
            status="error",
        )

    def _sleep_before_retry(self, attempt: int) -> None:
        if self.retry_backoff_sec <= 0:
            return
        time.sleep(self.retry_backoff_sec * attempt)

    def chat_completion(self, prompt: str, system_prompt: str = "", timeout_sec: int = 120) -> str:
        self._set_last_error("")
        if not self.base_url:
            self._set_last_error("Empty base_url.")
            return ""

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 2000,
            "stream": False,
        }

        total_attempts = max(1, self.max_retries + 1)
        for attempt in range(1, total_attempts + 1):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=timeout_sec)
                status_code = int(getattr(response, "status_code", 0) or 0)
                if self._is_retryable_status(status_code) and attempt < total_attempts:
                    self._set_last_error(
                        f"HTTP {status_code} from LLM endpoint (attempt {attempt}/{total_attempts})."
                    )
                    self._sleep_before_retry(attempt)
                    continue

                response.raise_for_status()
                result = response.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                if not isinstance(content, str):
                    self._set_last_error("Model response did not contain text content.")
                    self._log_client_error("llm_non_text_response", attempt, total_attempts)
                    return ""
                self._set_last_error("")
                return content
            except requests.exceptions.Timeout as exc:
                self._set_last_error(f"timeout: {exc}")
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                self._log_client_error("llm_timeout", attempt, total_attempts)
                return ""
            except requests.exceptions.ConnectionError as exc:
                self._set_last_error(f"connection_error: {exc}")
                if attempt < total_attempts and not self._is_non_retryable_connection_error(exc):
                    self._sleep_before_retry(attempt)
                    continue
                self._log_client_error("llm_connection_error", attempt, total_attempts)
                return ""
            except requests.exceptions.RequestException as exc:
                status_code = int(getattr(getattr(exc, "response", None), "status_code", 0) or 0)
                self._set_last_error(f"http_error[{status_code or 'unknown'}]: {exc}")
                if status_code and self._is_retryable_status(status_code) and attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                self._log_client_error("llm_http_error", attempt, total_attempts)
                return ""
            except Exception as exc:
                self._set_last_error(f"unexpected_error: {exc}")
                self._log_client_error("llm_unexpected_error", attempt, total_attempts)
                return ""

        return ""
