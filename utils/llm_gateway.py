import threading
import time
from typing import Optional

from utils.llm_client import LLMClient


class LLMGateway:
    """Provider-level gateway with basic rate limiting and circuit breaker."""

    def __init__(
        self,
        client: LLMClient,
        rpm_limit: int = 60,
        breaker_failure_threshold: int = 5,
        breaker_reset_sec: float = 30.0,
    ):
        self.client = client
        self.rpm_limit = max(0, int(rpm_limit))
        self.breaker_failure_threshold = max(1, int(breaker_failure_threshold))
        self.breaker_reset_sec = max(1.0, float(breaker_reset_sec))

        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self._next_allowed_ts = 0.0
        self._consecutive_failures = 0
        self._breaker_open_until = 0.0
        self.last_error = ""

    def _set_last_error(self, value: str) -> None:
        text = str(value or "")
        self._thread_local.last_error = text
        self.last_error = text

    def get_last_error(self) -> str:
        return str(getattr(self._thread_local, "last_error", self.last_error) or "")

    def _get_client_last_error(self) -> str:
        getter = getattr(self.client, "get_last_error", None)
        if callable(getter):
            return str(getter() or "")
        return str(getattr(self.client, "last_error", "") or "")

    def _wait_for_rate_limit(self) -> None:
        if self.rpm_limit <= 0:
            return

        min_interval = 60.0 / float(self.rpm_limit)
        while True:
            with self._lock:
                now = time.time()
                if now >= self._next_allowed_ts:
                    self._next_allowed_ts = now + min_interval
                    return
                wait_sec = max(0.0, self._next_allowed_ts - now)
            if wait_sec > 0:
                time.sleep(wait_sec)

    def _check_circuit_open(self) -> Optional[str]:
        with self._lock:
            now = time.time()
            if now < self._breaker_open_until:
                left = round(self._breaker_open_until - now, 2)
                return f"circuit_open: retry after {left}s"
            return None

    def _record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._breaker_open_until = 0.0

    def _record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.breaker_failure_threshold:
                self._breaker_open_until = time.time() + self.breaker_reset_sec

    def chat_completion(self, prompt: str, system_prompt: str = "", timeout_sec: int = 120) -> str:
        circuit_error = self._check_circuit_open()
        if circuit_error:
            self._set_last_error(circuit_error)
            return ""

        self._wait_for_rate_limit()
        content = self.client.chat_completion(prompt, system_prompt, timeout_sec=timeout_sec)
        last_error = self._get_client_last_error()

        if content.strip():
            self._record_success()
            self._set_last_error("")
            return content

        self._record_failure()
        self._set_last_error(last_error or "empty_response_from_provider")
        return ""
