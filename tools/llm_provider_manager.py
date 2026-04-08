#!/usr/bin/env python3
import argparse
import json
import os
import sys


def get_config_path():
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")


def load_config():
    config_path = get_config_path()
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config):
    config_path = get_config_path()
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    print(f"Config saved to {config_path}")


def list_providers(config):
    print("\n=== Available LLM Providers ===\n")
    providers = config.get("llm_providers", {}).get("providers", [])
    default = config.get("llm_providers", {}).get("default_provider", "")

    if not providers:
        print("No providers configured.")
        return

    print(f"{'Name':<20} {'Type':<20} {'Model':<25} {'Local':<8} {'Enabled':<8}")
    print("-" * 85)
    for p in providers:
        name = p.get("name", "")
        ptype = p.get("provider_type", "")
        model = p.get("model_name", "")
        is_local = "Yes" if p.get("is_local", False) else "No"
        enabled = "Yes" if p.get("enabled", False) else "No"
        marker = " *" if name == default else ""
        print(f"{name:<20} {ptype:<20} {model:<25} {is_local:<8} {enabled:<8}{marker}")

    print(f"\nDefault provider: {default}")
    print("\n(* = current default)")


def list_providers_verbose(config):
    print("\n=== Available LLM Providers (Verbose) ===\n")
    providers = config.get("llm_providers", {}).get("providers", [])
    default = config.get("llm_providers", {}).get("default_provider", "")
    fallbacks = config.get("llm_providers", {}).get("fallback_providers", [])

    if not providers:
        print("No providers configured.")
        return

    for i, p in enumerate(providers, 1):
        name = p.get("name", "")
        ptype = p.get("provider_type", "")
        model = p.get("model_name", "")
        base_url = p.get("base_url", "")
        is_local = p.get("is_local", False)
        enabled = p.get("enabled", False)
        has_key = bool(p.get("api_key", ""))

        print(f"{i}. {name}")
        print(f"   Type: {ptype}")
        print(f"   Model: {model}")
        print(f"   Base URL: {base_url}")
        print(f"   Local: {is_local}")
        print(f"   Enabled: {enabled}")
        print(f"   Has API Key: {has_key}")
        print(f"   Default: {name == default}")
        print(f"   Fallback: {name in fallbacks}")
        print()


def set_default_provider(config, provider_name):
    providers = config.get("llm_providers", {}).get("providers", [])
    provider_names = [p.get("name", "") for p in providers]

    if provider_name not in provider_names:
        print(f"Error: Provider '{provider_name}' not found.")
        print(f"Available providers: {', '.join(provider_names)}")
        sys.exit(1)

    if "llm_providers" not in config:
        config["llm_providers"] = {}
    config["llm_providers"]["default_provider"] = provider_name
    save_config(config)
    print(f"Default provider set to: {provider_name}")


def add_fallback(config, provider_name):
    providers = config.get("llm_providers", {}).get("providers", [])
    provider_names = [p.get("name", "") for p in providers]
    default = config.get("llm_providers", {}).get("default_provider", "")

    if provider_name not in provider_names:
        print(f"Error: Provider '{provider_name}' not found.")
        sys.exit(1)

    if provider_name == default:
        print(f"Error: Cannot add the default provider as a fallback.")
        sys.exit(1)

    fallbacks = config.get("llm_providers", {}).get("fallback_providers", [])
    if provider_name in fallbacks:
        print(f"Provider '{provider_name}' is already a fallback.")
        return

    fallbacks.append(provider_name)
    config["llm_providers"]["fallback_providers"] = fallbacks
    save_config(config)
    print(f"Added '{provider_name}' to fallback providers.")


def remove_fallback(config, provider_name):
    fallbacks = config.get("llm_providers", {}).get("fallback_providers", [])

    if provider_name not in fallbacks:
        print(f"Provider '{provider_name}' is not in fallback list.")
        return

    fallbacks.remove(provider_name)
    config["llm_providers"]["fallback_providers"] = fallbacks
    save_config(config)
    print(f"Removed '{provider_name}' from fallback providers.")


def enable_provider(config, provider_name):
    providers = config.get("llm_providers", {}).get("providers", [])

    for p in providers:
        if p.get("name") == provider_name:
            p["enabled"] = True
            save_config(config)
            print(f"Enabled provider: {provider_name}")
            return

    print(f"Error: Provider '{provider_name}' not found.")
    sys.exit(1)


def disable_provider(config, provider_name):
    providers = config.get("llm_providers", {}).get("providers", [])

    for p in providers:
        if p.get("name") == provider_name:
            p["enabled"] = False
            save_config(config)
            print(f"Disabled provider: {provider_name}")
            return

    print(f"Error: Provider '{provider_name}' not found.")
    sys.exit(1)


def check_providers():
    print("\n=== Checking Provider Health ===\n")
    try:
        from utils.llm_manager import get_multi_llm_manager
        manager = get_multi_llm_manager()
        results = manager.health_check_all()

        for name, result in results.items():
            status = "OK" if result["healthy"] else "FAIL"
            local = " (local)" if result.get("is_local") else ""
            print(f"  {name}: {status}{local}")
            print(f"    Model: {result.get('model', 'N/A')}")
            print(f"    Type: {result.get('provider_type', 'N/A')}")
            if result.get("error"):
                print(f"    Error: {result['error']}")
            print()
    except ImportError as exc:
        print(f"Error: Cannot import llm_manager: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"Error checking providers: {exc}")
        sys.exit(1)


def show_current():
    print("\n=== Current LLM Configuration ===\n")
    try:
        from utils.llm_manager import get_multi_llm_manager
        manager = get_multi_llm_manager()

        print(f"Active Provider: {manager.active_provider.provider_name if manager.active_provider else 'None'}")
        print(f"Model: {manager.active_provider.model_name if manager.active_provider else 'N/A'}")
        print(f"Base URL: {manager.active_provider.config.base_url if manager.active_provider else 'N/A'}")
        print(f"Timeout: {manager.active_provider.config.timeout_sec if manager.active_provider else 'N/A'}s")

        print(f"\nFallback Providers: {[p.provider_name for p in manager.fallback_providers]}")

        print("\nAll Available Providers:")
        for p in manager.get_available_providers():
            marker = " (active)" if manager.active_provider and p["name"] == manager.active_provider.provider_name else ""
            disabled = " (disabled)" if not p["enabled"] else ""
            print(f"  - {p['name']}: {p['model']}{marker}{disabled}")

    except ImportError as exc:
        print(f"Error: Cannot import llm_manager: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)


def add_path_prefix():
    import sys
    import os
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)


def main():
    add_path_prefix()

    parser = argparse.ArgumentParser(
        description="LLM Provider Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("list", help="List all configured providers")
    subparsers.add_parser("list-verbose", help="List all providers with detailed info")
    subparsers.add_parser("status", help="Check health status of all providers")
    subparsers.add_parser("current", help="Show current active provider configuration")

    set_default = subparsers.add_parser("set-default", help="Set the default provider")
    set_default.add_argument("provider", help="Provider name to set as default")

    add_fb = subparsers.add_parser("add-fallback", help="Add a provider to fallback list")
    add_fb.add_argument("provider", help="Provider name to add as fallback")

    rm_fb = subparsers.add_parser("remove-fallback", help="Remove a provider from fallback list")
    rm_fb.add_argument("provider", help="Provider name to remove from fallback")

    enable = subparsers.add_parser("enable", help="Enable a provider")
    enable.add_argument("provider", help="Provider name to enable")

    disable = subparsers.add_parser("disable", help="Disable a provider")
    disable.add_argument("provider", help="Provider name to disable")

    args = parser.parse_args()

    if args.command == "list":
        config = load_config()
        list_providers(config)
    elif args.command == "list-verbose":
        config = load_config()
        list_providers_verbose(config)
    elif args.command == "status":
        check_providers()
    elif args.command == "current":
        show_current()
    elif args.command == "set-default":
        config = load_config()
        set_default_provider(config, args.provider)
    elif args.command == "add-fallback":
        config = load_config()
        add_fallback(config, args.provider)
    elif args.command == "remove-fallback":
        config = load_config()
        remove_fallback(config, args.provider)
    elif args.command == "enable":
        config = load_config()
        enable_provider(config, args.provider)
    elif args.command == "disable":
        config = load_config()
        disable_provider(config, args.provider)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
