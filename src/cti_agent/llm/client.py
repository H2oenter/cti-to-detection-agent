"""The model interface, and the implementations behind it.

Stages talk to `LLMClient`, never to an SDK. Swapping the public API for an
enterprise endpoint (Part B) means adding another implementation here and
choosing it in config.

There are no tool definitions anywhere in this module: the collector gets
structured output and nothing else (design rule 2).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Protocol, TypeVar

import anthropic
from pydantic import BaseModel, ValidationError

from cti_agent.util.normalise import canonical_json, sha256_bytes

T = TypeVar("T", bound=BaseModel)


class FatalLLMError(Exception):
    """Configuration problems (bad key, unknown model, bad request): stop the run."""


class FixtureMissing(Exception):
    pass


@dataclass
class LLMResult(Generic[T]):
    parsed: T | None
    stop_reason: str  # end_turn, refusal, max_tokens, invalid_output, error
    input_tokens: int
    output_tokens: int
    latency_ms: int
    model: str
    detail: str | None = None


class LLMClient(Protocol):
    def structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int,
        effort: str | None = None,
    ) -> LLMResult[T]: ...


class AnthropicClient:
    def __init__(self, api_key: str | None = None, max_retries: int = 3, timeout: float = 300):
        # api_key=None lets the SDK resolve credentials from the environment.
        self._client = anthropic.Anthropic(
            api_key=api_key, max_retries=max_retries, timeout=timeout
        )

    def structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int,
        effort: str | None = None,
    ) -> LLMResult[T]:
        start = time.perf_counter()
        try:
            response = self._client.messages.parse(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_format=schema,
                **({"output_config": {"effort": effort}} if effort else {}),
            )
        except (
            anthropic.AuthenticationError,
            anthropic.PermissionDeniedError,
            anthropic.NotFoundError,
            anthropic.BadRequestError,
        ) as exc:
            raise FatalLLMError(f"{type(exc).__name__}: {exc.message}") from exc
        except (ValidationError, json.JSONDecodeError) as exc:
            # The SDK parses the output itself; a truncated or malformed body lands here.
            return LLMResult(None, "invalid_output", 0, 0, _ms(start), model, str(exc)[:200])
        except anthropic.APIError as exc:  # retries exhausted: rate limit, overload, network
            return LLMResult(None, "error", 0, 0, _ms(start), model, type(exc).__name__)

        detail = None
        parsed = None
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            detail = f"refusal category: {getattr(details, 'category', None)}"
        elif response.stop_reason == "max_tokens":
            detail = "output hit max_tokens"
        else:
            parsed = response.parsed_output
        return LLMResult(
            parsed=parsed,
            stop_reason=response.stop_reason or "unknown",
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            latency_ms=_ms(start),
            model=response.model,
            detail=detail,
        )


def request_key(model: str, system: str, user: str) -> str:
    """Identifies a request for record/replay. Changing a prompt changes the key."""
    payload = canonical_json({"model": model, "system": system, "user": user})
    return sha256_bytes(payload.encode("utf-8"))


class RecordingClient:
    """Wraps a real client and saves each response as a test fixture (outputs only, no keys)."""

    def __init__(self, inner: LLMClient, fixture_dir: Path) -> None:
        self.inner = inner
        self.fixture_dir = fixture_dir
        fixture_dir.mkdir(parents=True, exist_ok=True)

    def structured(self, *, model, system, user, schema, max_tokens, effort=None):
        result = self.inner.structured(
            model=model,
            system=system,
            user=user,
            schema=schema,
            max_tokens=max_tokens,
            effort=effort,
        )
        key = request_key(model, system, user)
        record = {
            "request_key": key,
            "model": result.model,
            "stop_reason": result.stop_reason,
            "detail": result.detail,
            "usage": {"input_tokens": result.input_tokens, "output_tokens": result.output_tokens},
            "output": result.parsed.model_dump(mode="json") if result.parsed else None,
        }
        path = self.fixture_dir / f"{key[:16]}.json"
        path.write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return result


class ReplayClient:
    """Serves recorded responses so tests and CI never call the API."""

    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = fixture_dir

    def structured(self, *, model, system, user, schema, max_tokens, effort=None):
        key = request_key(model, system, user)
        path = self.fixture_dir / f"{key[:16]}.json"
        if not path.exists():
            raise FixtureMissing(
                f"no recorded response {path.name} in {self.fixture_dir}; "
                "the prompt or input changed, so record again with --record"
            )
        record = json.loads(path.read_text(encoding="utf-8"))
        output = record["output"]
        return LLMResult(
            parsed=schema.model_validate(output) if output is not None else None,
            stop_reason=record["stop_reason"],
            input_tokens=record["usage"]["input_tokens"],
            output_tokens=record["usage"]["output_tokens"],
            latency_ms=0,
            model=record["model"],
            detail=record.get("detail"),
        )


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
