import copy
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, Optional

from utils.structured_logging import get_logger, log_event


@dataclass
class AgentRunStrategy:
    retries: int = 0
    retry_backoff_sec: float = 0.0
    timeout_sec: Optional[float] = None
    failure_policy: str = "raise"  # raise | return_error


class AgentCoordinator:
    """In-process coordinator with retry/timeout/failure-policy controls and metrics."""

    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.agent_strategies: Dict[str, AgentRunStrategy] = {}
        self._metrics_lock = Lock()
        self._metrics: Dict[str, Any] = {
            "total_calls": 0,
            "total_failures": 0,
            "total_retries": 0,
            "total_timeouts": 0,
            "per_agent": {},
        }
        self.logger = get_logger("vuldetection.orchestrator")

    def register_agent(self, agent: Any, strategy: Optional[AgentRunStrategy] = None) -> None:
        agent_name = agent.__class__.__name__
        self.agents[agent_name] = agent
        self.agent_strategies[agent_name] = strategy or AgentRunStrategy()
        self._ensure_agent_metrics(agent_name)

    def set_agent_strategy(self, agent_name: str, strategy: AgentRunStrategy) -> None:
        self.agent_strategies[agent_name] = strategy
        self._ensure_agent_metrics(agent_name)

    def snapshot_metrics(self) -> Dict[str, Any]:
        with self._metrics_lock:
            return copy.deepcopy(self._metrics)

    @staticmethod
    def diff_metrics(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, int]:
        return {
            "agent_calls": int(after.get("total_calls", 0) or 0) - int(before.get("total_calls", 0) or 0),
            "agent_failures": int(after.get("total_failures", 0) or 0)
            - int(before.get("total_failures", 0) or 0),
            "agent_retries": int(after.get("total_retries", 0) or 0) - int(before.get("total_retries", 0) or 0),
            "agent_timeouts": int(after.get("total_timeouts", 0) or 0) - int(before.get("total_timeouts", 0) or 0),
        }

    def _ensure_agent_metrics(self, agent_name: str) -> None:
        with self._metrics_lock:
            self._metrics["per_agent"].setdefault(
                agent_name,
                {
                    "calls": 0,
                    "failures": 0,
                    "retries": 0,
                    "timeouts": 0,
                },
            )

    def _inc_metric(self, agent_name: str, key: str, amount: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[key] += amount
            self._metrics["per_agent"][agent_name][key.replace("total_", "")] += amount

    @staticmethod
    def _normalize_failure_policy(value: str) -> str:
        text = str(value or "raise").strip().lower()
        return text if text in {"raise", "return_error"} else "raise"

    @staticmethod
    def _is_timeout_enabled(timeout_sec: Optional[float]) -> bool:
        return timeout_sec is not None and float(timeout_sec) > 0

    def _run_once(
        self,
        agent: Any,
        input_data: Dict[str, Any],
        timeout_sec: Optional[float],
    ) -> Dict[str, Any]:
        if not self._is_timeout_enabled(timeout_sec):
            return agent.run(input_data) or {}

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(agent.run, input_data)
            return future.result(timeout=float(timeout_sec)) or {}

    def run_agent(
        self,
        agent_name: str,
        input_data: Dict[str, Any],
        retries: Optional[int] = None,
        retry_backoff_sec: Optional[float] = None,
        timeout_sec: Optional[float] = None,
        failure_policy: Optional[str] = None,
    ) -> Dict[str, Any]:
        if agent_name not in self.agents:
            raise ValueError(f"Agent {agent_name} not registered")

        strategy = self.agent_strategies.get(agent_name, AgentRunStrategy())
        eff_retries = strategy.retries if retries is None else int(retries)
        eff_backoff = strategy.retry_backoff_sec if retry_backoff_sec is None else float(retry_backoff_sec)
        eff_timeout = strategy.timeout_sec if timeout_sec is None else timeout_sec
        eff_failure_policy = self._normalize_failure_policy(
            strategy.failure_policy if failure_policy is None else failure_policy
        )

        eff_retries = max(0, int(eff_retries or 0))
        eff_backoff = max(0.0, float(eff_backoff or 0.0))
        total_attempts = max(1, eff_retries + 1)

        self._inc_metric(agent_name, "total_calls", 1)
        last_exc: Exception | None = None
        failure_reason = ""
        failed_attempts = 0
        timeout_attempts = 0

        for attempt in range(1, total_attempts + 1):
            start = time.perf_counter()
            log_event(
                self.logger,
                "agent_run_start",
                agent=agent_name,
                attempt=attempt,
                timeout_sec=eff_timeout,
                failure_policy=eff_failure_policy,
            )
            try:
                result = self._run_once(self.agents[agent_name], input_data, eff_timeout)
                elapsed_ms = (time.perf_counter() - start) * 1000.0

                result.setdefault("_runtime", {})
                result["_runtime"].update(
                    {
                        "agent": agent_name,
                        "attempt": attempt,
                        "elapsed_ms": round(elapsed_ms, 2),
                        "retried": attempt > 1,
                        "failed_attempts": failed_attempts,
                        "timeout_attempts": timeout_attempts,
                        "failure_policy": eff_failure_policy,
                        "timeout_sec": eff_timeout,
                    }
                )
                log_event(
                    self.logger,
                    "agent_run_success",
                    agent=agent_name,
                    attempt=attempt,
                    elapsed_ms=round(elapsed_ms, 2),
                    status="ok",
                )
                return result
            except FutureTimeoutError as exc:
                last_exc = exc
                failed_attempts += 1
                timeout_attempts += 1
                failure_reason = f"timeout after {eff_timeout}s"
                self._inc_metric(agent_name, "total_failures", 1)
                self._inc_metric(agent_name, "total_timeouts", 1)
                log_event(
                    self.logger,
                    "agent_run_timeout",
                    agent=agent_name,
                    attempt=attempt,
                    timeout_sec=eff_timeout,
                    status="timeout",
                )
            except Exception as exc:  # pragma: no cover - defensive path
                last_exc = exc
                failed_attempts += 1
                failure_reason = str(exc)
                self._inc_metric(agent_name, "total_failures", 1)
                log_event(
                    self.logger,
                    "agent_run_failure",
                    agent=agent_name,
                    attempt=attempt,
                    status="error",
                    error=str(exc),
                )

            if attempt < total_attempts:
                self._inc_metric(agent_name, "total_retries", 1)
                if eff_backoff > 0:
                    time.sleep(eff_backoff * attempt)

        failure_text = (
            f"{agent_name} failed after {total_attempts} attempt(s): "
            f"{failure_reason or str(last_exc) or 'unknown_error'}"
        )

        runtime = {
            "agent": agent_name,
            "attempt": total_attempts,
            "elapsed_ms": 0.0,
            "retried": total_attempts > 1,
            "failed_attempts": failed_attempts,
            "timeout_attempts": timeout_attempts,
            "failure_policy": eff_failure_policy,
            "timeout_sec": eff_timeout,
            "status": "failed",
        }
        if eff_failure_policy == "return_error":
            log_event(
                self.logger,
                "agent_run_exhausted",
                agent=agent_name,
                attempts=total_attempts,
                status="return_error",
                error=failure_text,
            )
            return {
                "error": failure_text,
                "_runtime": runtime,
            }

        raise RuntimeError(failure_text)
