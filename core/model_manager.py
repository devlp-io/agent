"""
core.model_manager — model provider configuration, fallback chain, and streaming LLM client.
Preserves .env, never hardcodes keys, and translates raw errors into clear actionable messages.
"""
import os
import re
import time
import pathlib
import threading
from typing import Generator, List, Dict, Tuple, Optional
import httpx
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


def _default_variants(model: str) -> List[Dict[str, str]]:
    return [
        {"key": "quick", "label": "Quick", "model": model, "effort": "low"},
        {"key": "balanced", "label": "Balanced", "model": model, "effort": "high"},
        {"key": "deep", "label": "Deep", "model": model, "effort": "max"},
    ]


def _parse_variants(raw: str, model: str) -> List[Dict[str, str]]:
    """Parse `quick=Label~model~effort;balanced=...` into ordered variant dicts."""
    if not raw:
        return []
    out: List[Dict[str, str]] = []
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, rest = chunk.split("=", 1)
        key = key.strip().lower()
        if key not in ("quick", "balanced", "deep"):
            continue
        bits = rest.split("~")
        label = (bits[0] or key.title()).strip()
        v_model = (bits[1].strip() if len(bits) > 1 else "") or model
        v_effort = (bits[2].strip() if len(bits) > 2 else "") or ""
        out.append({"key": key, "label": label, "model": v_model, "effort": v_effort})
    order = {"quick": 0, "balanced": 1, "deep": 2}
    out.sort(key=lambda v: order.get(v["key"], 9))
    return out


class ModelConfig:
    def __init__(self, name: str, model: str, base_url: str, key_var: str,
                 variants: Optional[List[Dict[str, str]]] = None,
                 price_in: float = 0.0, price_out: float = 0.0):
        self.name = name
        self.model = model
        self.base_url = base_url
        self.key_var = key_var
        self.variants = variants or _default_variants(model)
        self.price_in = float(price_in or 0.0)
        self.price_out = float(price_out or 0.0)

    @property
    def api_key(self) -> str:
        # Provider-specific key only. DEEPSEEK_KEY and the generic AG_KEY are
        # aliases for DeepSeek; other providers must set their own variable so
        # a DeepSeek key never marks Gemini/OpenAI/etc. as configured.
        if self.key_var == "DEEPSEEK_KEY":
            return os.environ.get("DEEPSEEK_KEY") or os.environ.get("AG_KEY") or ""
        if self.key_var == "AG_KEY":
            return os.environ.get("AG_KEY") or ""
        return os.environ.get(self.key_var) or ""

    @property
    def is_configured(self) -> bool:
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key)


# Process-wide usage accumulator. Every ModelManager instance (agent router,
# chat stream, title/summary helpers) records here; the server snapshots the
# totals around a run and attributes the delta to that thread.
GLOBAL_USAGE: Dict[str, float] = {
    "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "requests": 0,
}
USAGE_LOCK = threading.Lock()
_EMPTY_USAGE = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "requests": 0}


def usage_snapshot() -> Dict[str, float]:
    with USAGE_LOCK:
        return dict(GLOBAL_USAGE)


def usage_delta(before: Dict[str, float]) -> Dict[str, float]:
    after = usage_snapshot()
    return {k: float(after.get(k, 0)) - float(before.get(k, 0)) for k in _EMPTY_USAGE}


class ModelManager:
    """Manages active models, profiles from models.conf, and streaming requests."""

    def __init__(self):
        self.profiles: Dict[str, ModelConfig] = {}
        self._reasoning_cb = None
        self.usage_totals = dict(_EMPTY_USAGE)
        self.model_override: Optional[str] = None
        self._stream_lock = threading.Lock()
        self._active_stream = None
        self._abort = False
        self._load_profiles()
        self.active_profile_name = "deepseek-flash"
        self.effort = os.environ.get("AG_REASONING_EFFORT", "high")
        self._sync_from_env()

    @staticmethod
    def _to_price(value: str) -> float:
        try:
            return max(0.0, float(value))
        except Exception:
            return 0.0

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
                    variants = _parse_variants(parts[4], model) if len(parts) > 4 else []
                    price_in = self._to_price(parts[5]) if len(parts) > 5 else 0.0
                    price_out = self._to_price(parts[6]) if len(parts) > 6 else 0.0
                    self.profiles[name] = ModelConfig(
                        name, model, base, key_var, variants, price_in, price_out
                    )

        # Fallback defaults if conf missing
        if "deepseek-flash" not in self.profiles:
            self.profiles["deepseek-flash"] = ModelConfig(
                "deepseek-flash", "deepseek-flash", "https://api.deepseek.com/v1", "DEEPSEEK_KEY"
            )
        if "deepseek-pro" not in self.profiles:
            self.profiles["deepseek-pro"] = ModelConfig(
                "deepseek-pro", "deepseek-v4-pro", "https://api.deepseek.com/v1", "DEEPSEEK_KEY"
            )
        if "ollama" not in self.profiles:
            self.profiles["ollama"] = ModelConfig(
                "ollama", "dolphin3", "http://localhost:11434/v1", "OLLAMA_KEY"
            )

    def add_custom_model(self, name: str, base_url: Optional[str] = None) -> ModelConfig:
        """Register an arbitrary model id as a usable profile and activate it."""
        base = base_url or os.environ.get("AG_BASE") or "https://api.deepseek.com/v1"
        # A custom DeepSeek model must read DEEPSEEK_KEY, not only AG_KEY.
        key_var = "DEEPSEEK_KEY" if "deepseek" in base.lower() else "AG_KEY"
        cfg = ModelConfig(name=name, model=name, base_url=base, key_var=key_var)
        self.profiles[name] = cfg
        self.active_profile_name = name
        return cfg

    def _sync_from_env(self):
        env_model = os.environ.get("AG_MODEL")
        env_base = os.environ.get("AG_BASE")

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
                self.add_custom_model(env_model, env_base)

    def set_effort(self, effort: str) -> None:
        """Reasoning effort for models that support it (low | high | max)."""
        if effort in ("low", "high", "max"):
            self.effort = effort

    def set_reasoning_callback(self, cb) -> None:
        """Register a callback receiving streamed reasoning_content (thinking)."""
        self._reasoning_cb = cb

    def _emit_reasoning(self, text: str) -> None:
        cb = getattr(self, "_reasoning_cb", None)
        if cb and text:
            try:
                cb(text)
            except Exception:
                pass

    @property
    def active_config(self) -> ModelConfig:
        cfg = self.profiles.get(self.active_profile_name)
        if cfg is not None:
            return cfg
        return self.profiles.get("deepseek-flash") or next(iter(self.profiles.values()))

    @property
    def display_name(self) -> str:
        return self.model_override or self.active_config.model

    @property
    def active_model_id(self) -> str:
        return self.model_override or self.active_config.model

    def resolve_variant(self, key: Optional[str]) -> Dict[str, str]:
        """Return the selected variant dict for the active profile (or {})."""
        if not key:
            return {}
        for v in self.active_config.variants:
            if v.get("key") == key:
                return v
        return {}

    def apply_variant(self, key: Optional[str]) -> None:
        """Select a variant: model override + reasoning effort for this manager."""
        v = self.resolve_variant(key)
        if not v:
            self.model_override = None
            return
        model = (v.get("model") or "").strip()
        self.model_override = model if model and model != self.active_config.model else None
        effort = (v.get("effort") or "").strip()
        if effort:
            self.set_effort(effort)

    def record_usage(self, usage, cfg: Optional[ModelConfig] = None) -> None:
        """Accumulate token usage and estimated cost for this manager and globally."""
        if usage is None:
            return
        cfg = cfg or self.active_config
        try:
            p = int(getattr(usage, "prompt_tokens", 0) or 0)
            c = int(getattr(usage, "completion_tokens", 0) or 0)
        except Exception:
            return
        if p <= 0 and c <= 0:
            return
        price_cfg = cfg
        if self.model_override:
            for prof in self.profiles.values():
                if prof.model == self.model_override:
                    price_cfg = prof
                    break
        cost = (p / 1_000_000.0) * price_cfg.price_in + (c / 1_000_000.0) * price_cfg.price_out
        with USAGE_LOCK:
            GLOBAL_USAGE["prompt_tokens"] += p
            GLOBAL_USAGE["completion_tokens"] += c
            GLOBAL_USAGE["cost_usd"] += cost
            GLOBAL_USAGE["requests"] += 1
        self.usage_totals["prompt_tokens"] += p
        self.usage_totals["completion_tokens"] += c
        self.usage_totals["cost_usd"] += cost
        self.usage_totals["requests"] += 1

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
        target = (model_or_profile or "").strip()
        self.model_override = None
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
                f"API key missing for {cfg.name} (set {cfg.key_var} in .env or Settings)"
            )
        model = self.model_override or cfg.model
        # A stalled provider stream must raise instead of hanging the agent
        # forever. Read timeout is per chunk; connect is separate.
        read_timeout = float(os.environ.get("AG_LLM_TIMEOUT", "90") or 90)
        timeout = httpx.Timeout(read_timeout, connect=20.0, write=30.0, pool=20.0)
        return OpenAI(base_url=cfg.base_url, api_key=key or "dummy-key",
                      timeout=timeout, max_retries=0), model

    def get_client(self) -> Tuple[OpenAI, str]:
        return self.get_client_for(self.active_config)

    def cancel_stream(self) -> None:
        """Close the active provider stream so a stalled call unblocks."""
        with self._stream_lock:
            self._abort = True
            resp = self._active_stream
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass

    def stream_chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> Generator[str, None, None]:
        with self._stream_lock:
            self._abort = False
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
                    extra = {}
                    if model in ("deepseek-flash", "deepseek-v4-pro", "deepseek-v4"):
                        extra["reasoning_effort"] = getattr(self, "effort", "high") or "high"
                    request = dict(
                        model=model,
                        messages=messages,
                        stream=True,
                        temperature=temperature,
                        **extra,
                    )
                    # OpenAI-compatible usage on the final chunk. Providers that
                    # reject the option are retried once without it.
                    try:
                        response = client.chat.completions.create(
                            stream_options={"include_usage": True}, **request
                        )
                    except Exception as opt_err:
                        low = str(opt_err).lower()
                        if any(t in low for t in ("stream_options", "unknown parameter",
                                                  "unrecognized", "extra fields", "extra inputs",
                                                  "not permitted", "unexpected keyword",
                                                  "unsupported", "invalid_request")):
                            response = client.chat.completions.create(**request)
                        else:
                            raise
                    has_yielded = False
                    silence_limit = float(os.environ.get("AG_LLM_SILENCE", "75") or 75)
                    last_signal = time.time()
                    with self._stream_lock:
                        self._active_stream = response
                    try:
                        for chunk in response:
                            if self._abort:
                                return
                            usage = getattr(chunk, "usage", None)
                            if usage is not None:
                                self.record_usage(usage, cfg)
                            if not chunk.choices:
                                if time.time() - last_signal > silence_limit:
                                    raise TimeoutError("model stream silent timeout")
                                continue
                            delta = chunk.choices[0].delta
                            if delta is None:
                                if time.time() - last_signal > silence_limit:
                                    raise TimeoutError("model stream silent timeout")
                                continue
                            reasoning = getattr(delta, "reasoning_content", None)
                            if reasoning:
                                last_signal = time.time()
                                self._emit_reasoning(reasoning)
                            if delta.content:
                                last_signal = time.time()
                                has_yielded = True
                                yield delta.content
                    finally:
                        with self._stream_lock:
                            if self._active_stream is response:
                                self._active_stream = None
                    if self._abort:
                        return
                    if has_yielded:
                        return
                except Exception as e:
                    if self._abort:
                        return
                    err_str = str(e)
                    last_error = e
                    is_rate_limit = "429" in err_str or "rate_limit" in err_str.lower()
                    is_timeout = ("timeout" in err_str.lower() or "timed out" in err_str.lower()
                                  or "APITimeout" in err_str)
                    if (is_rate_limit or is_timeout) and attempt < max_retries - 1:
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
        keys = ["DEEPSEEK_KEY", "AG_KEY", "GEMINI_KEY", "OPENAI_KEY", "ANTHROPIC_KEY", "OPENROUTER_KEY", "OLLAMA_KEY"]
        res = {}
        for k in keys:
            val = os.environ.get(k, "")
            if val:
                res[k] = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
            else:
                res[k] = "(not set)"
        return res
