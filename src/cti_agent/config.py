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
    cache_read_per_mtok: float | None = None  # if not 0.1x input


# USD per million tokens, first-party API rates. Override with MODEL_PRICES='{"model": {...}}'.
DEFAULT_PRICES = {
    "claude-haiku-5-5": ModelPrice(input_per_mtok=0.10, output_per_mtok=0.50),
    "claude-sonnet-5-5": ModelPrice(input_per_mtok=2.00, output_per_mtok=10.00),
    "claude-opus-5-5": ModelPrice(
        input_per_mtok=4.00, output_per_mtok=20.00, cache_read_per_mtok=0.20
    ),
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
    analyse_effort: Literal["low", "medium", "high"] = "medium"
    review_effort: Literal["low", "medium", "high"] = "medium"
    analyse_max_output_tokens: int = 16_000
    max_hunts_per_run: int = 5

    # Second checks, on a different and stronger model than the first pass, so they don't
    # share its blind spots. Both can only remove or flag, never add.
    recheck_indicators: bool = True
    recheck_model: str = "claude-opus-5-5"
    recheck_effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    recheck_max_output_tokens: int = 8_000
    review2_model: str = "claude-opus-5-5"
    review2_effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"

    max_tokens_per_run: int = 300_000
    chunk_target_tokens: int = 8_000
    chunk_overlap_ratio: float = 0.1

    # Part B: TLP:AMBER only goes to an endpoint approved for confidential data.
    endpoint_approved_for_amber: bool = False

    # publish --apply only. A separate identity from anything that reads: it needs
    # Microsoft Sentinel Contributor on this workspace and nothing else.
    sentinel_workspace_id: str | None = None
    publish_azure_tenant_id: str | None = None
    publish_azure_client_id: str | None = None
    publish_azure_client_secret: SecretStr | None = None
    publish_azure_certificate_path: Path | None = None

    # cti-agent slack: a bot in one private channel, run from this machine in Socket Mode.
    slack_bot_token: SecretStr | None = None  # xoxb-…
    slack_app_token: SecretStr | None = None  # xapp-…, with connections:write
    slack_channel_id: str | None = None
    slack_users: str = ""  # who may use it: member IDs and names, "U...=YourName,U...=Colleague"
    slack_approved_for_amber: bool = False  # TLP:AMBER content may be posted in that channel
    slack_daily_spend_cap_usd: float = 5.0  # all of today's model spend (UTC), any interface
    slack_upload_dir: Path = Path("reports/slack")

    model_prices: dict[str, ModelPrice] = Field(default_factory=lambda: dict(DEFAULT_PRICES))

    attack_bundle: Path = Path("data/attack/enterprise-attack.json")
    attack_mobile_bundle: Path | None = Path("data/attack/mobile-attack.json")
    allowlist_file: Path = Path("data/allowlist.txt")
    rules_file: Path = Path("data/my_rules.sample.csv")
    kql_schema_file: Path = Path("data/kql_schema.json")
    sources_file: Path = Path("data/sources.toml")
    watchlist_file: Path = Path("data/watchlist.toml")
    inbox_dir: Path = Path("reports/inbox")
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

    def estimate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        *,
        unpriced_as_dearest: bool = False,
    ) -> float | None:
        """None for a model with no price, or with `unpriced_as_dearest`, the dearest listed
        price: a spend total must never count an unknown model as free."""
        price = self.model_prices.get(model)
        if price is None and unpriced_as_dearest and self.model_prices:
            price = max(self.model_prices.values(),
                        key=lambda p: (p.output_per_mtok, p.input_per_mtok))  # fmt: skip
        if price is None:
            return None
        # Prompt-cache writes cost 1.25x the input price; reads 0.1x unless the model says.
        effective_input = input_tokens + 1.25 * cache_write_tokens
        read_price = price.cache_read_per_mtok
        if read_price is None:
            read_price = 0.1 * price.input_per_mtok
        return (
            effective_input * price.input_per_mtok
            + cache_read_tokens * read_price
            + output_tokens * price.output_per_mtok
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
