import json

from utils.benchmark import evaluate_reports
from utils.llm_manager import MultiLLMManager


def _write_config(path, providers, default_provider="deepseek", fallback_providers=None):
    payload = {
        "deepseek_api_key": "",
        "llm_providers": {
            "providers": providers,
            "default_provider": default_provider,
            "fallback_providers": fallback_providers or [],
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_preflight_reports_missing_api_key_without_network(tmp_path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("health check should fail before making a network request")

    monkeypatch.setattr("utils.llm_providers.openai_provider.requests.get", fail_if_called)
    config_path = tmp_path / "config.json"
    _write_config(
        config_path,
        [
            {
                "name": "deepseek",
                "provider_type": "openai_compatible",
                "model_name": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com",
                "api_key": "",
                "enabled": True,
                "is_local": False,
            }
        ],
    )

    manager = MultiLLMManager(config_path=str(config_path))
    result = manager.preflight_health_check()

    assert manager.providers["deepseek"].model_name == "deepseek-v4-pro"
    assert result["ready"] is False
    assert "Missing API key" in result["providers"]["deepseek"]["error"]


def test_provider_api_key_can_come_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    config_path = tmp_path / "config.json"
    _write_config(
        config_path,
        [
            {
                "name": "deepseek",
                "provider_type": "openai_compatible",
                "model_name": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com",
                "api_key": "",
                "enabled": True,
                "is_local": False,
            }
        ],
    )

    manager = MultiLLMManager(config_path=str(config_path))

    assert manager.providers["deepseek"].model_name == "deepseek-v4-pro"
    assert manager.providers["deepseek"].config.base_url == "https://api.deepseek.com"
    assert manager.providers["deepseek"].config.api_key == "sk-test"


def test_preflight_selects_healthy_fallback(tmp_path, monkeypatch):
    def fake_health_check(self):
        if self.config.name == "openai":
            return True
        self.set_last_error("simulated unhealthy provider")
        return False

    monkeypatch.setattr("utils.llm_providers.openai_provider.OpenAICompatibleProvider.health_check", fake_health_check)
    config_path = tmp_path / "config.json"
    _write_config(
        config_path,
        [
            {
                "name": "deepseek",
                "provider_type": "openai_compatible",
                "model_name": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com",
                "api_key": "sk-deepseek",
                "enabled": True,
                "is_local": False,
            },
            {
                "name": "openai",
                "provider_type": "openai_compatible",
                "model_name": "gpt-4o",
                "base_url": "https://api.openai.com/v1",
                "api_key": "sk-openai",
                "enabled": True,
                "is_local": False,
            },
        ],
        default_provider="deepseek",
        fallback_providers=["openai"],
    )

    manager = MultiLLMManager(config_path=str(config_path))
    result = manager.preflight_health_check()

    assert result["ready"] is True
    assert result["selected_provider"] == "openai"
    assert manager.active_provider.provider_name == "openai"


def test_phase1_benchmark_metrics_match_by_file_and_line():
    labels = {
        "labels": [
            {
                "id": "L1",
                "file": "data/test_codes/test_10_vulnerabilities.c",
                "line": 9,
                "cwe_id": "CWE-120",
                "is_vulnerable": True,
            },
            {
                "id": "L2",
                "file": "data/test_codes/test_10_vulnerabilities.c",
                "line": 35,
                "cwe_id": "CWE-134",
                "is_vulnerable": True,
            },
        ]
    }
    reports = {
        "reports": [
            {
                "file": "C:/repo/data/test_codes/test_10_vulnerabilities.c",
                "line": 10,
                "cwe_id": "CWE-120",
                "risk_level": "High",
                "confidence": 0.9,
            },
            {
                "file": "C:/repo/data/test_codes/test_10_vulnerabilities.c",
                "line": 80,
                "cwe_id": "CWE-999",
                "risk_level": "Medium",
                "confidence": 0.8,
            },
        ]
    }

    metrics = evaluate_reports(reports, labels, line_tolerance=2)

    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
