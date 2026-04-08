import time
import requests
from typing import Optional
from utils.llm_provider import LLMProvider, LLMProviderConfig, LLMProviderFactory
from utils.structured_logging import get_logger, log_event


LOGGER = get_logger("vuldetection.llm_ollama")


class OllamaProvider(LLMProvider):
    PROVIDER_TYPE = "ollama"

    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self.max_retries = config.max_retries
        self.retry_backoff_sec = config.retry_backoff_sec
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens

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

        url = f"{base_url}/api/chat"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }

        timeout = timeout_sec or self.config.timeout_sec
        total_attempts = max(1, self.max_retries + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                response = requests.post(url, json=payload, timeout=timeout)
                status_code = int(getattr(response, "status_code", 0) or 0)

                if status_code == 404:
                    return self._chat_completion_v1(base_url, payload, timeout)

                if status_code >= 500 and attempt < total_attempts:
                    self.set_last_error(f"HTTP {status_code} from Ollama (attempt {attempt}/{total_attempts}).")
                    self._sleep_before_retry(attempt)
                    continue

                response.raise_for_status()
                result = response.json()

                content = ""
                if "message" in result:
                    content = result["message"].get("content", "")
                elif "response" in result:
                    content = result["response"]

                if not isinstance(content, str):
                    self.set_last_error("Model response did not contain text content.")
                    return ""

                self.set_last_error("")
                log_event(
                    LOGGER,
                    "ollama_completion_success",
                    model=self.config.model_name,
                    content_length=len(content),
                )
                return content

            except requests.exceptions.Timeout as exc:
                self.set_last_error(f"timeout: {exc}")
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                log_event(LOGGER, "ollama_timeout", model=self.config.model_name, status="error")
                return ""

            except requests.exceptions.ConnectionError as exc:
                self.set_last_error(f"connection_error: {exc}")
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                log_event(LOGGER, "ollama_connection_error", model=self.config.model_name, status="error")
                return ""

            except Exception as exc:
                self.set_last_error(f"unexpected_error: {exc}")
                log_event(LOGGER, "ollama_unexpected_error", model=self.config.model_name, status="error", error=str(exc))
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                return ""

        return ""

    def _chat_completion_v1(self, base_url: str, payload: dict, timeout: int) -> str:
        url = f"{base_url}/v1/chat/completions"
        messages = payload.get("messages", [])

        v1_payload = {
            "model": payload.get("model"),
            "messages": messages,
            "stream": False,
        }

        try:
            response = requests.post(url, json=v1_payload, timeout=timeout)
            response.raise_for_status()
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            return content if isinstance(content, str) else ""
        except Exception:
            return ""

    def health_check(self) -> bool:
        base_url = self.config.base_url.rstrip("/")
        if not base_url:
            return False

        try:
            url = f"{base_url}/api/tags"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                models = response.json()
                available = [m.get("name", "") for m in models.get("models", [])]
                log_event(
                    LOGGER,
                    "ollama_health_check",
                    status="ok",
                    available_models=available,
                )
                return True
            return False
        except Exception as exc:
            log_event(LOGGER, "ollama_health_check", status="error", error=str(exc))
            return False

    def list_models(self) -> list:
        base_url = self.config.base_url.rstrip("/")
        try:
            url = f"{base_url}/api/tags"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                models = response.json()
                return [m.get("name", "") for m in models.get("models", [])]
        except Exception:
            pass
        return []


class OllamaGenerateProvider(OllamaProvider):
    PROVIDER_TYPE = "ollama_generate"

    def chat_completion(self, prompt: str, system_prompt: str = "", timeout_sec: Optional[int] = None) -> str:
        self.set_last_error("")
        base_url = self.config.base_url.rstrip("/")
        if not base_url:
            self.set_last_error("Empty base_url.")
            return ""

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        url = f"{base_url}/api/generate"
        payload = {
            "model": self.config.model_name,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }

        timeout = timeout_sec or self.config.timeout_sec
        total_attempts = max(1, self.max_retries + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                response = requests.post(url, json=payload, timeout=timeout)
                response.raise_for_status()
                result = response.json()
                content = result.get("response", "")
                if not isinstance(content, str):
                    return ""
                self.set_last_error("")
                return content

            except Exception as exc:
                self.set_last_error(f"ollama_generate_error: {exc}")
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                return ""

        return ""


LLMProviderFactory.register("ollama", OllamaProvider)
LLMProviderFactory.register("ollama_generate", OllamaGenerateProvider)
