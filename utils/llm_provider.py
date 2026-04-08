import os
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class LLMProviderConfig:
    name: str
    provider_type: str
    model_name: str
    base_url: str
    api_key: str = ""
    max_retries: int = 2
    retry_backoff_sec: float = 0.8
    timeout_sec: int = 120
    rpm_limit: int = 60
    temperature: float = 0.1
    max_tokens: int = 2000
    enabled: bool = True
    is_local: bool = False
    extra_config: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LLMProviderConfig":
        return cls(
            name=str(data.get("name", "")),
            provider_type=str(data.get("provider_type", "openai_compatible")),
            model_name=str(data.get("model_name", "")),
            base_url=str(data.get("base_url", "")),
            api_key=str(data.get("api_key", "")),
            max_retries=int(data.get("max_retries", 2)),
            retry_backoff_sec=float(data.get("retry_backoff_sec", 0.8)),
            timeout_sec=int(data.get("timeout_sec", 120)),
            rpm_limit=int(data.get("rpm_limit", 60)),
            temperature=float(data.get("temperature", 0.1)),
            max_tokens=int(data.get("max_tokens", 2000)),
            enabled=bool(data.get("enabled", True)),
            is_local=bool(data.get("is_local", False)),
            extra_config=data.get("extra_config", {}),
        )


class LLMProvider(ABC):
    PROVIDER_TYPE: str = "base"

    def __init__(self, config: LLMProviderConfig):
        self.config = config
        self.last_error: str = ""

    @abstractmethod
    def chat_completion(self, prompt: str, system_prompt: str = "", timeout_sec: Optional[int] = None) -> str:
        pass

    @abstractmethod
    def health_check(self) -> bool:
        pass

    def get_last_error(self) -> str:
        return self.last_error

    def set_last_error(self, error: str) -> None:
        self.last_error = str(error)

    @property
    def model_name(self) -> str:
        return self.config.model_name

    @property
    def provider_name(self) -> str:
        return self.config.name


class LLMProviderFactory:
    _registry: Dict[str, type] = {}

    @classmethod
    def register(cls, provider_type: str, provider_class: type) -> None:
        cls._registry[provider_type.lower()] = provider_class

    @classmethod
    def create(cls, config: LLMProviderConfig) -> LLMProvider:
        provider_type = config.provider_type.lower()
        if provider_type not in cls._registry:
            available = ", ".join(cls._registry.keys()) or "none"
            raise ValueError(f"Unknown provider type: '{provider_type}'. Available: {available}")
        return cls._registry[provider_type](config)

    @classmethod
    def available_providers(cls) -> List[str]:
        return list(cls._registry.keys())


class MultiLLMManager:
    def __init__(self):
        self.providers: Dict[str, LLMProvider] = {}
        self.active_provider: Optional[LLMProvider] = None
        self.fallback_providers: List[LLMProvider] = []
        self._load_config()

    def _load_config(self) -> None:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
        if not os.path.exists(config_path):
            self._create_default_config(config_path)
            return

        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        llm_config = config_data.get("llm_providers", {})
        provider_list = llm_config.get("providers", [])
        default_provider = llm_config.get("default_provider", "")

        for provider_data in provider_list:
            provider_cfg = LLMProviderConfig.from_dict(provider_data)
            if not provider_cfg.enabled:
                continue
            try:
                provider = LLMProviderFactory.create(provider_cfg)
                self.providers[provider_cfg.name] = provider
            except Exception as exc:
                print(f"[MultiLLMManager] Failed to load provider '{provider_cfg.name}': {exc}")
                continue

        if default_provider and default_provider in self.providers:
            self.active_provider = self.providers[default_provider]
        elif self.providers:
            self.active_provider = next(iter(self.providers.values()))

        fallback_names = llm_config.get("fallback_providers", [])
        for name in fallback_names:
            if name in self.providers and self.providers[name] != self.active_provider:
                self.fallback_providers.append(self.providers[name])

    def _create_default_config(self, config_path: str) -> None:
        default_config = {
            "deepseek_api_key": "",
            "llm_providers": {
                "providers": [
                    {
                        "name": "deepseek",
                        "provider_type": "openai_compatible",
                        "model_name": "deepseek-coder",
                        "base_url": "https://api.deepseek.com/v1",
                        "api_key": "",
                        "enabled": True,
                        "is_local": False,
                    },
                    {
                        "name": "ollama",
                        "provider_type": "ollama",
                        "model_name": "codellama",
                        "base_url": "http://localhost:11434",
                        "enabled": False,
                        "is_local": True,
                    },
                ],
                "default_provider": "deepseek",
                "fallback_providers": [],
            }
        }
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)
        print(f"[MultiLLMManager] Created default config at {config_path}")

    def set_active_provider(self, provider_name: str) -> bool:
        if provider_name not in self.providers:
            return False
        self.active_provider = self.providers[provider_name]
        return True

    def call_with_fallback(
        self,
        prompt: str,
        system_prompt: str = "",
        timeout_sec: Optional[int] = None,
    ) -> tuple[str, str]:
        errors = []

        if self.active_provider:
            result = self._call_provider(self.active_provider, prompt, system_prompt, timeout_sec)
            if result[0]:
                return result
            errors.append(f"{self.active_provider.provider_name}: {result[1]}")

        for provider in self.fallback_providers:
            result = self._call_provider(provider, prompt, system_prompt, timeout_sec)
            if result[0]:
                return result
            errors.append(f"{provider.provider_name}: {result[1]}")

        return "", "; ".join(errors) if errors else "No provider available"

    def _call_provider(
        self,
        provider: LLMProvider,
        prompt: str,
        system_prompt: str,
        timeout_sec: Optional[int],
    ) -> tuple[str, str]:
        try:
            timeout = timeout_sec or provider.config.timeout_sec
            result = provider.chat_completion(prompt, system_prompt, timeout_sec=timeout)
            if result.strip():
                return result, ""
            return "", provider.get_last_error() or "empty response"
        except Exception as exc:
            return "", str(exc)

    def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        results = {}
        for name, provider in self.providers.items():
            is_healthy = False
            error_msg = ""
            try:
                is_healthy = provider.health_check()
            except Exception as exc:
                is_healthy = False
                error_msg = str(exc)
            results[name] = {
                "healthy": is_healthy,
                "error": error_msg,
                "model": provider.model_name,
                "is_local": provider.config.is_local,
                "provider_type": provider.config.provider_type,
            }
        return results

    def get_available_providers(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "model": p.model_name,
                "enabled": p.config.enabled,
                "is_local": p.config.is_local,
                "provider_type": p.config.provider_type,
            }
            for name, p in self.providers.items()
        ]


def get_multi_llm_manager() -> MultiLLMManager:
    return MultiLLMManager()
