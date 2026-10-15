"""Runtime settings, read from environment variables.

On Cloud Run every secret is injected from Secret Manager with
--set-secrets; locally they come from your shell. Nothing is hard-coded
and keys are never logged. A missing key simply disables that check.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    safe_browsing_key: str
    virustotal_key: str
    urlhaus_key: str
    gemini_key: str
    gemini_model: str
    llm_enabled: bool
    intel_timeout: float  # seconds per reputation check
    llm_timeout: float


def get_settings() -> Settings:
    env = os.environ.get
    return Settings(
        safe_browsing_key=env("SAFE_BROWSING_API_KEY", ""),
        virustotal_key=env("VIRUSTOTAL_API_KEY", ""),
        urlhaus_key=env("URLHAUS_API_KEY", ""),
        gemini_key=env("GEMINI_API_KEY", ""),
        gemini_model=env("GEMINI_MODEL", "gemini-3.5-flash-lite"),
        # Off by default: it is the only check that sends email text to a third
        # party, and the Gemini API is not free on billed projects. Opt in explicitly.
        llm_enabled=env("LLM_ENABLED", "false").lower() == "true",
        intel_timeout=float(env("INTEL_TIMEOUT_SECONDS", "5")),
        llm_timeout=float(env("LLM_TIMEOUT_SECONDS", "10")),
    )
