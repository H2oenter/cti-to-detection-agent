"""The model interface, and the implementations behind it.

Stages talk to `LLMClient`, never to an SDK. Swapping the public API for an
enterprise endpoint (Part B) means adding another implementation here and
choosing it in config.

There are no tool definitions anywhere in this module: every model gets
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

# Server-side refusal fallback ("default" routing). Threat-intel text can trip safety
# classifiers; with this, a declined request is re-run on a fallback model in the same call.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


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
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


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
        refusal_fallback: bool = False,
    ) -> LLMResult[T]: ...


class AnthropicClient:
    def __init__(
        self,
        api_key: str | None = None,
        workspace_id: str | None = None,
        max_retries: int = 3,
        timeout: float = 300,
    ):
        # api_key=None lets the SDK resolve credentials from the environment. Keys that
        # aren't scoped to a workspace must name one on every request.
        headers = {"anthropic-workspace-id": workspace_id} if workspace_id else None
        self._client = anthropic.Anthropic(
            api_key=api_key, default_headers=headers, max_retries=max_retries, timeout=timeout
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
        refusal_fallback: bool = False,
    ) -> LLMResult[T]:
        start = time.perf_counter()
        request = {
            "model": model,
            "max_tokens": max_tokens,
            # Cached: the system prompt is the stable prefix shared by every call of a stage.
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user}],
            "output_format": schema,
        }
        if effort:
            request["output_config"] = {"effort": effort}
        try:
            if refusal_fallback:
                response = self._client.beta.messages.parse(
                    **request, betas=[FALLBACK_BETA], fallbacks="default"
                )
            else:
                response = self._client.messages.parse(**request)
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

        notes = []
        parsed = None
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            notes.append(f"refusal category: {getattr(details, 'category', None)}")
        elif response.stop_reason == "max_tokens":
            notes.append("output hit max_tokens")
        else:
            parsed = response.parsed_output
        if response.model != model:
            notes.append(f"refusal fallback: answered by {response.model}")
        usage = response.usage
        return LLMResult(
            parsed=parsed,
            stop_reason=response.stop_reason or "unknown",
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            latency_ms=_ms(start),
            model=response.model,
            detail="; ".join(notes) or None,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", None) or 0,
            cache_write_tokens=getattr(usage, "cache_creation_input_tokens", None) or 0,
        )


def request_key(model: str, system: str, user: str) -> str:
    """Identifies a request for record/replay. Changing a prompt changes the key."""
    payload = canonical_json({"model": model, "system": system, "user": user})
    return sha256_bytes(payload.encode("utf-8"))


def _save_record(fixture_dir: Path, key: str, result: LLMResult) -> None:
    """Outputs and token counts only: never request headers or credentials."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "request_key": key,
        "model": result.model,
        "stop_reason": result.stop_reason,
        "detail": result.detail,
        "usage": {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cache_read_tokens": result.cache_read_tokens,
            "cache_write_tokens": result.cache_write_tokens,
        },
        "output": result.parsed.model_dump(mode="json") if result.parsed else None,
    }
    path = fixture_dir / f"{key[:16]}.json"
    path.write_text(json.dumps(record, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


class RecordingClient:
    """Wraps a real client and saves each response as a test fixture."""

    def __init__(self, inner: LLMClient, fixture_dir: Path) -> None:
        self.inner = inner
        self.fixture_dir = fixture_dir
        fixture_dir.mkdir(parents=True, exist_ok=True)

    def structured(self, *, model, system, user, schema, max_tokens, effort=None, **kwargs):
        result = self.inner.structured(
            model=model,
            system=system,
            user=user,
            schema=schema,
            max_tokens=max_tokens,
            effort=effort,
            **kwargs,
        )
        _save_record(self.fixture_dir, request_key(model, system, user), result)
        return result


class ReplayClient:
    """Serves recorded responses so tests and CI never call the API.

    With a `fallback` client, a request that has no recording goes to the fallback and its
    response is recorded: re-recording only what changed instead of the whole run.
    """

    def __init__(self, fixture_dir: Path, fallback: LLMClient | None = None) -> None:
        self.fixture_dir = fixture_dir
        self.fallback = fallback

    def structured(self, *, model, system, user, schema, max_tokens, effort=None, **kwargs):
        key = request_key(model, system, user)
        path = self.fixture_dir / f"{key[:16]}.json"
        if not path.exists() and self.fallback is not None:
            result = self.fallback.structured(
                model=model,
                system=system,
                user=user,
                schema=schema,
                max_tokens=max_tokens,
                effort=effort,
                **kwargs,
            )
            _save_record(self.fixture_dir, key, result)
            return result
        if not path.exists():
            raise FixtureMissing(
                f"no recorded response {path.name} in {self.fixture_dir}; "
                "the prompt or input changed, so record again with --record"
            )
        record = json.loads(path.read_text(encoding="utf-8"))
        output = record["output"]
        usage = record["usage"]
        return LLMResult(
            parsed=schema.model_validate(output) if output is not None else None,
            stop_reason=record["stop_reason"],
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            latency_ms=0,
            model=record["model"],
            detail="; ".join(filter(None, ["replayed", record.get("detail")])),
            cache_read_tokens=usage.get("cache_read_tokens", 0),
            cache_write_tokens=usage.get("cache_write_tokens", 0),
        )


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
