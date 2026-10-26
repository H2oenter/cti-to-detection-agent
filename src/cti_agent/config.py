"""Runtime configuration. Values come from the environment or .env, never from code."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from cti_agent.models import TLP


class ModelPrice(BaseModel):
    input_per_mtok: float
    output_per_mtok: float


# USD per million tokens, first-party API rates. Override with MODEL_PRICES='{"model": {...}}'.
DEFAULT_PRICES = {
    "claude-haiku-5-5": ModelPrice(input_per_mtok=0.10, output_per_mtok=0.50),
    "claude-sonnet-5-5": ModelPrice(input_per_mtok=2.00, output_per_mtok=10.00),
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    anthropic_api_key: SecretStr | None = None
    # Needed only when the key isn't scoped to a workspace (Console > Settings > Workspaces).
    anthropic_workspace_id: str | None = None

    extract_model: str = "claude-haiku-5-5"
    analyse_model: str = "claude-sonnet-5-5"
    review_model: str = "claude-sonnet-5-5"
    extract_effort: Literal["low", "medium", "high"] = "medium"
    extract_max_output_tokens: int = 16_000

    max_tokens_per_run: int = 300_000
    chunk_target_tokens: int = 8_000
    chunk_overlap_ratio: float = 0.1

    # Part B: TLP:AMBER only goes to an endpoint approved for confidential data.
    endpoint_approved_for_amber: bool = False

    model_prices: dict[str, ModelPrice] = Field(default_factory=lambda: dict(DEFAULT_PRICES))

    attack_bundle: Path = Path("data/attack/enterprise-attack.json")
    attack_mobile_bundle: Path | None = Path("data/attack/mobile-attack.json")
    allowlist_file: Path = Path("data/allowlist.txt")
    rules_file: Path = Path("data/my_rules.sample.csv")
    out_dir: Path = Path("out")

    @property
    def db_path(self) -> Path:
        return self.out_dir / "cti_agent.db"

    def attack_bundles(self) -> list[Path]:
        """Enterprise is required; Mobile is used once it has been downloaded."""
        bundles = [self.attack_bundle]
        if self.attack_mobile_bundle and self.attack_mobile_bundle.exists():
            bundles.append(self.attack_mobile_bundle)
        return bundles

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float | None:
        price = self.model_prices.get(model)
        if price is None:
            return None
        return (
            input_tokens * price.input_per_mtok + output_tokens * price.output_per_mtok
        ) / 1_000_000


def tlp_block_reason(tlp: TLP, settings: Settings) -> str | None:
    """Why this TLP may not be sent to the configured model endpoint, or None if it may."""
    if tlp == "RED":
        return "TLP:RED never goes to a third-party model."
    if tlp in ("AMBER", "AMBER+STRICT") and not settings.endpoint_approved_for_amber:
        return (
            f"TLP:{tlp} needs an endpoint approved for confidential data. "
            "Set ENDPOINT_APPROVED_FOR_AMBER=true only if yours is."
        )
    return None
