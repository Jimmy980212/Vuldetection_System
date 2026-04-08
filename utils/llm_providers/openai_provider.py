import time
import requests
from typing import Optional
from utils.llm_provider import LLMProvider, LLMProviderConfig, LLMProviderFactory
from utils.structured_logging import get_logger, log_event


LOGGER = get_logger("vuldetection.llm_openai")


class OpenAICompatibleProvider(LLMProvider):
    PROVIDER_TYPE = "openai_compatible"

    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self.max_retries = config.max_retries
        self.retry_backoff_sec = config.retry_backoff_sec
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens
        self._thread_local_errors = {}

    def _is_retryable_status(self, status_code: int) -> bool:
        return status_code in {408, 409, 425, 429, 500, 502, 503, 504}

    def _is_non_retryable_connection_error(self, exc: Exception) -> bool:
        text = str(exc or "").lower()
        hard_fail_markers = {
            "winerror 10013",
            "e_accessdenied",
            "permission denied",
            "access denied",
            "access was denied",
            "forbidden by access permissions",
        }
        return any(marker in text for marker in hard_fail_markers)

    def _to_safe_console_text(self, value: str) -> str:
        return str(value or "").encode("ascii", "backslashreplace").decode("ascii")

    def _sleep_before_retry(self, attempt: int) -> None:
        if self.retry_backoff_sec <= 0:
            return
        time.sleep(self.retry_backoff_sec * attempt)

    def chat_completion(self, prompt: str, system_prompt: str = "", timeout_sec: Optional[int] = None) -> str:
        self.set_last_error("")
        base_url = self.config.base_url.rstrip("/")
        if not base_url:
            self.set_last_error("Empty base_url.")
            return ""

        url = f"{base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }

        timeout = timeout_sec or self.config.timeout_sec
        total_attempts = max(1, self.max_retries + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=timeout)
                status_code = int(getattr(response, "status_code", 0) or 0)

                if self._is_retryable_status(status_code) and attempt < total_attempts:
                    self.set_last_error(f"HTTP {status_code} from LLM endpoint (attempt {attempt}/{total_attempts}).")
                    self._sleep_before_retry(attempt)
                    continue

                response.raise_for_status()
                result = response.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")

                if not isinstance(content, str):
                    self.set_last_error("Model response did not contain text content.")
                    log_event(LOGGER, "llm_non_text_response", model=self.config.model_name, status="error")
                    return ""

                self.set_last_error("")
                return content

            except requests.exceptions.Timeout as exc:
                self.set_last_error(f"timeout: {exc}")
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                log_event(LOGGER, "llm_timeout", model=self.config.model_name, status="error")
                return ""

            except requests.exceptions.ConnectionError as exc:
                self.set_last_error(f"connection_error: {exc}")
                if attempt < total_attempts and not self._is_non_retryable_connection_error(exc):
                    self._sleep_before_retry(attempt)
                    continue
                log_event(LOGGER, "llm_connection_error", model=self.config.model_name, status="error")
                return ""

            except requests.exceptions.RequestException as exc:
                status_code = int(getattr(getattr(exc, "response", None), "status_code", 0) or 0)
                self.set_last_error(f"http_error[{status_code or 'unknown'}]: {exc}")
                if status_code and self._is_retryable_status(status_code) and attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                log_event(LOGGER, "llm_http_error", model=self.config.model_name, status="error", error=str(exc))
                return ""

            except Exception as exc:
                self.set_last_error(f"unexpected_error: {exc}")
                log_event(LOGGER, "llm_unexpected_error", model=self.config.model_name, status="error", error=str(exc))
                return ""

        return ""

    def health_check(self) -> bool:
        base_url = self.config.base_url.rstrip("/")
        if not base_url:
            return False

        try:
            url = f"{base_url}/models"
            headers = {}
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"

            response = requests.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception:
            return False


class AzureOpenAIProvider(OpenAICompatibleProvider):
    PROVIDER_TYPE = "azure_openai"

    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self.api_version = config.extra_config.get("api_version", "2024-02-01")

    def chat_completion(self, prompt: str, system_prompt: str = "", timeout_sec: Optional[int] = None) -> str:
        self.set_last_error("")
        base_url = self.config.base_url.rstrip("/")
        if not base_url:
            self.set_last_error("Empty base_url.")
            return ""

        url = f"{base_url}/chat/completions?api-version={self.api_version}"
        headers = {
            "Content-Type": "application/json",
            "api-key": self.config.api_key,
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        timeout = timeout_sec or self.config.timeout_sec
        total_attempts = max(1, self.max_retries + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=timeout)
                status_code = int(getattr(response, "status_code", 0) or 0)

                if self._is_retryable_status(status_code) and attempt < total_attempts:
                    self.set_last_error(f"HTTP {status_code} from Azure OpenAI (attempt {attempt}/{total_attempts}).")
                    self._sleep_before_retry(attempt)
                    continue

                response.raise_for_status()
                result = response.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")

                if not isinstance(content, str):
                    self.set_last_error("Model response did not contain text content.")
                    return ""

                self.set_last_error("")
                return content

            except Exception as exc:
                self.set_last_error(f"azure_error: {exc}")
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                return ""

        return ""


LLMProviderFactory.register("openai_compatible", OpenAICompatibleProvider)
LLMProviderFactory.register("openai", OpenAICompatibleProvider)
LLMProviderFactory.register("azure_openai", AzureOpenAIProvider)
