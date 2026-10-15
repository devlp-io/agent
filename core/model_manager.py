"""
core.model_manager — model provider configuration, fallback chain, and streaming LLM client.
Preserves .env, never hardcodes keys, and translates raw errors into clear actionable messages.
"""
import os
import re
import time
import pathlib
from typing import Generator, List, Dict, Tuple, Optional
from openai import OpenAI

HERE = pathlib.Path(__file__).resolve().parent.parent

# Safely load .env without overriding shell environment
try:
    from dotenv import load_dotenv
    env_file = HERE / ".env"
    if env_file.exists():
        load_dotenv(env_file, override=False)
except Exception:
    pass


class ModelConfig:
    def __init__(self, name: str, model: str, base_url: str, key_var: str):
        self.name = name
        self.model = model
        self.base_url = base_url
        self.key_var = key_var

    @property
    def api_key(self) -> str:
        # Check AG_KEY first, then specific key_var, then DEEPSEEK_KEY for deepseek
        if self.key_var == "DEEPSEEK_KEY":
            return os.environ.get("AG_KEY") or os.environ.get("DEEPSEEK_KEY") or ""
        return os.environ.get(self.key_var) or os.environ.get("AG_KEY") or ""

    @property
    def is_configured(self) -> bool:
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key)


class ModelManager:
    """Manages active models, profiles from models.conf, and streaming requests."""

    def __init__(self):
        self.profiles: Dict[str, ModelConfig] = {}
        self._load_profiles()
        self.active_profile_name = "deepseek"
        self._sync_from_env()

    def _load_profiles(self):
        conf_file = HERE / "models.conf"
        if conf_file.exists():
            for line in conf_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 4:
                    name, model, base, key_var = parts[:4]
                    self.profiles[name] = ModelConfig(name, model, base, key_var)

        # Fallback defaults if conf missing
        if "deepseek" not in self.profiles:
            self.profiles["deepseek"] = ModelConfig(
                "deepseek", "deepseek-chat", "https://api.deepseek.com/v1", "DEEPSEEK_KEY"
            )
        if "deepseek-reasoner" not in self.profiles:
            self.profiles["deepseek-reasoner"] = ModelConfig(
                "deepseek-reasoner", "deepseek-reasoner", "https://api.deepseek.com/v1", "DEEPSEEK_KEY"
            )
        if "ollama" not in self.profiles:
            self.profiles["ollama"] = ModelConfig(
                "ollama", "dolphin3", "http://localhost:11434/v1", "OLLAMA_KEY"
            )

    def _sync_from_env(self):
        env_model = os.environ.get("AG_MODEL")
        env_base = os.environ.get("AG_BASE")
        env_key = os.environ.get("AG_KEY") or os.environ.get("DEEPSEEK_KEY")

        if env_model:
            # Check if matches any existing profile
            found = False
            for p_name, cfg in self.profiles.items():
                if cfg.model == env_model:
                    self.active_profile_name = p_name
                    if env_base:
                        cfg.base_url = env_base
                    found = True
                    break
            if not found:
                custom_cfg = ModelConfig(
                    name=env_model,
                    model=env_model,
                    base_url=env_base or "https://api.deepseek.com/v1",
                    key_var="AG_KEY"
                )
                self.profiles[env_model] = custom_cfg
                self.active_profile_name = env_model

    @property
    def active_config(self) -> ModelConfig:
        return self.profiles.get(self.active_profile_name) or self.profiles["deepseek"]

    @property
    def display_name(self) -> str:
        return self.active_config.model

    @property
    def provider_name(self) -> str:
        base = self.active_config.base_url.lower()
        if "deepseek" in base:
            return "deepseek"
        if "generativelanguage" in base or "google" in base:
            return "google"
        if "openrouter" in base:
            return "openrouter"
        if "anthropic" in base:
            return "anthropic"
        if "openai" in base:
            return "openai"
        if "localhost" in base or "127.0.0.1" in base:
            return "ollama"
        return "custom"

    def set_model(self, model_or_profile: str) -> Tuple[bool, str]:
        target = model_or_profile.strip()
        if target in self.profiles:
            self.active_profile_name = target
            os.environ["AG_MODEL"] = self.active_config.model
            os.environ["AG_BASE"] = self.active_config.base_url
            return True, f"Switched to profile '{target}' ({self.active_config.model})"

        # Search by model name
        for p_name, cfg in self.profiles.items():
            if cfg.model.lower() == target.lower():
                self.active_profile_name = p_name
                os.environ["AG_MODEL"] = cfg.model
                os.environ["AG_BASE"] = cfg.base_url
                return True, f"Switched to model '{cfg.model}'"

        available = ", ".join(list(self.profiles.keys())[:8])
        return False, f"Unknown model '{target}'. Available: {available}..."

    def get_client_for(self, cfg: ModelConfig) -> Tuple[OpenAI, str]:
        key = cfg.api_key
        if not key and not ("localhost" in cfg.base_url or "127.0.0.1" in cfg.base_url):
            raise ValueError(
                f"API key missing for {cfg.name} (checked {cfg.key_var} and AG_KEY in environment and .env)"
            )
        return OpenAI(base_url=cfg.base_url, api_key=key or "dummy-key"), cfg.model

    def get_client(self) -> Tuple[OpenAI, str]:
        return self.get_client_for(self.active_config)

    def stream_chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> Generator[str, None, None]:
        # Build candidate configurations: active profile first, then any other configured profiles
        candidates = [self.active_config]
        for name, cfg in self.profiles.items():
            if name != self.active_profile_name and cfg.is_configured:
                candidates.append(cfg)

        last_error = None
        for cfg_idx, cfg in enumerate(candidates):
            try:
                if cfg_idx == 0:
                    client, model = self.get_client()
                else:
                    client, model = self.get_client_for(cfg)
            except Exception as e:
                last_error = e
                continue

            # Exponential backoff retry on transient 429 rate limits
            max_retries = 2 if cfg_idx == 0 else 1
            for attempt in range(max_retries):
                try:
                    response = client.chat.completions.create(
                        model=model,
                        messages=messages,
                        stream=True,
                        temperature=temperature,
                    )
                    has_yielded = False
                    for chunk in response:
                        if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                            has_yielded = True
                            yield chunk.choices[0].delta.content
                    if has_yielded:
                        return
                except Exception as e:
                    err_str = str(e)
                    last_error = e
                    is_rate_limit = "429" in err_str or "rate_limit" in err_str.lower()
                    if is_rate_limit and attempt < max_retries - 1:
                        backoff = 2.0 * (attempt + 1)
                        time.sleep(backoff)
                        continue
                    break

        # If all candidates exhausted, raise translated error
        err_str = str(last_error) if last_error else "No responsive model profile configured"
        if "AuthenticationError" in err_str or "invalid_api_key" in err_str or "401" in err_str:
            raise RuntimeError(f"Authentication failed: Check your API key in .env or environment ({self.active_config.key_var})")
        elif "429" in err_str or "rate_limit" in err_str.lower():
            raise RuntimeError("Rate limit reached (HTTP 429). Target/model throttled. Please wait a moment.")
        elif "insufficient_quota" in err_str.lower() or "balance" in err_str.lower():
            raise RuntimeError("Insufficient balance / quota on model provider account.")
        elif "ConnectTimeout" in err_str or "timeout" in err_str.lower():
            raise RuntimeError(f"Connection timeout to {self.active_config.base_url}. Verify network connectivity.")
        else:
            raise RuntimeError(f"LLM API Error: {err_str}")

    def save_key(self, key: str, key_var: Optional[str] = None) -> Tuple[bool, str]:
        """Save and export API key to runtime environment and persist to .env safely."""
        key = key.strip()
        if not key:
            return False, "API key cannot be empty"

        target_var = key_var or self.active_config.key_var or "DEEPSEEK_KEY"
        os.environ[target_var] = key
        if target_var == "DEEPSEEK_KEY":
            os.environ["AG_KEY"] = key

        env_file = HERE / ".env"
        try:
            content = ""
            if env_file.exists():
                content = env_file.read_text(encoding="utf-8")
            else:
                examples_file = HERE / ".env.examples"
                if examples_file.exists():
                    content = examples_file.read_text(encoding="utf-8")

            # Update line if already present
            pattern = rf"^({re.escape(target_var)}=).*$"
            if re.search(pattern, content, flags=re.MULTILINE):
                content = re.sub(pattern, rf"\g<1>{key}", content, flags=re.MULTILINE)
            else:
                content += f"\n{target_var}={key}\n"

            if target_var == "DEEPSEEK_KEY" and "AG_KEY=" not in content:
                content += f"AG_KEY={key}\n"

            env_file.write_text(content, encoding="utf-8")
            masked = key[:4] + "..." + key[-4:] if len(key) > 8 else "***"
            return True, f"Successfully saved {target_var}={masked} to .env and activated!"
        except Exception as e:
            return False, f"Key set in runtime memory, but failed to write .env: {e}"

    def get_env_status(self) -> Dict[str, str]:
        """Get masked status of configured environment variables."""
        keys = ["DEEPSEEK_KEY", "AG_KEY", "GEMINI_KEY", "OPENAI_KEY", "ANTHROPIC_KEY", "OPENROUTER_KEY"]
        res = {}
        for k in keys:
            val = os.environ.get(k, "")
            if val:
                res[k] = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
            else:
                res[k] = "(not set)"
        return res
