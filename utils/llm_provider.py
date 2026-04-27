import json
import os
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
        extra_config = data.get("extra_config", {}) or {}
        if not isinstance(extra_config, dict):
            extra_config = {}

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
            extra_config=extra_config,
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
    PLACEHOLDER_KEYS = {"", "YOUR_API_KEY_HERE", "your_api_key_here", "your-api-key-here"}

    def __init__(self, config_path: Optional[str] = None):
        self.providers: Dict[str, LLMProvider] = {}
        self.active_provider: Optional[LLMProvider] = None
        self.fallback_providers: List[LLMProvider] = []
        self.config_path = config_path or os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
        self._load_config()

    def _load_config(self) -> None:
        config_path = self.config_path
        if not os.path.exists(config_path):
            self._create_default_config(config_path)

        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        llm_config = config_data.get("llm_providers", {})
        provider_list = llm_config.get("providers", [])
        default_provider = llm_config.get("default_provider", "")

        for provider_data in provider_list:
            provider_cfg = LLMProviderConfig.from_dict(provider_data)
            if not provider_cfg.enabled:
                continue
            provider_cfg.api_key = self._resolve_api_key(provider_cfg, config_data)
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

    @classmethod
    def _is_placeholder_key(cls, value: str) -> bool:
        return str(value or "").strip() in cls.PLACEHOLDER_KEYS

    def _resolve_api_key(self, provider_cfg: LLMProviderConfig, config_data: Dict[str, Any]) -> str:
        configured = str(provider_cfg.api_key or "").strip()
        if configured.lower().startswith("env:"):
            return os.getenv(configured.split(":", 1)[1].strip(), "")
        if configured and not self._is_placeholder_key(configured):
            return configured

        env_candidates = []
        explicit_env = provider_cfg.extra_config.get("api_key_env")
        if explicit_env:
            env_candidates.append(str(explicit_env))

        provider_token = provider_cfg.name.upper().replace("-", "_")
        env_candidates.extend(
            [
                f"VULDET_{provider_token}_API_KEY",
                f"{provider_token}_API_KEY",
            ]
        )

        provider_type = provider_cfg.provider_type.lower()
        if provider_type in {"openai_compatible", "openai"} and provider_cfg.name.lower() == "openai":
            env_candidates.append("OPENAI_API_KEY")
        if provider_cfg.name.lower() == "deepseek":
            env_candidates.insert(0, "DEEPSEEK_API_KEY")
            root_key = str(config_data.get("deepseek_api_key", "") or "").strip()
            if root_key and not self._is_placeholder_key(root_key):
                return root_key
        if provider_type == "azure_openai":
            env_candidates.append("AZURE_OPENAI_API_KEY")

        for env_name in env_candidates:
            value = os.getenv(env_name, "").strip()
            if value and not self._is_placeholder_key(value):
                return value
        return ""

    def _create_default_config(self, config_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
        default_config = {
            "deepseek_api_key": "",
            "llm_providers": {
                "providers": [
                    {
                        "name": "deepseek",
                        "provider_type": "openai_compatible",
                        "model_name": "deepseek-v4-pro",
                        "base_url": "https://api.deepseek.com",
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
            if not is_healthy and not error_msg:
                error_msg = provider.get_last_error()
            results[name] = {
                "healthy": is_healthy,
                "error": error_msg or "",
                "model": provider.model_name,
                "is_local": provider.config.is_local,
                "provider_type": provider.config.provider_type,
                "is_active": provider == self.active_provider,
                "is_fallback": provider in self.fallback_providers,
            }
        return results

    def preflight_health_check(self) -> Dict[str, Any]:
        results = self.health_check_all()
        healthy = [name for name, info in results.items() if info.get("healthy")]

        selected_name = ""
        if self.active_provider and self.active_provider.provider_name in healthy:
            selected_name = self.active_provider.provider_name
        else:
            for provider in self.fallback_providers:
                if provider.provider_name in healthy:
                    selected_name = provider.provider_name
                    break
            if not selected_name and healthy:
                selected_name = healthy[0]

        if selected_name:
            self.set_active_provider(selected_name)

        errors = []
        for name, info in results.items():
            if not info.get("healthy"):
                error = info.get("error") or "health check failed"
                errors.append(f"{name}: {error}")

        return {
            "ready": bool(selected_name),
            "selected_provider": selected_name,
            "active_provider": self.active_provider.provider_name if self.active_provider else "",
            "healthy_providers": healthy,
            "providers": results,
            "errors": errors,
        }

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


def get_multi_llm_manager(config_path: Optional[str] = None) -> MultiLLMManager:
    return MultiLLMManager(config_path=config_path)
