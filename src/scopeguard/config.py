"""Assessment file schema. Structural checks live here; scope policy does not."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from scopeguard.errors import ConfigError
from scopeguard.normalize import (
    NormalizationError,
    is_ip,
    normalize_host,
    normalize_path,
    parse_http_url,
)

_PARAM = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_MARKER = re.compile(r"^SG_[A-Z0-9_]{6,64}$")
_MAX_CONFIG_BYTES = 1_000_000
Port = Annotated[int, Field(ge=1, le=65535)]


class _StrictLoader(yaml.SafeLoader):
    """Safe YAML that rejects aliases and duplicate keys."""

    def compose_node(self, parent: yaml.nodes.Node | None, index: int | None) -> yaml.nodes.Node:
        if self.check_event(yaml.events.AliasEvent):
            raise ConfigError("YAML aliases are not permitted")
        return super().compose_node(parent, index)


def _construct_mapping(
    loader: yaml.SafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[str, Any]:
    seen: set[object] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ConfigError(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)  # type: ignore[no-any-return]


_StrictLoader.construct_mapping = _construct_mapping  # type: ignore[assignment]


def _reject_aliases(node: yaml.nodes.Node) -> None:
    if node.id == "alias":
        raise ConfigError("YAML aliases are not permitted")
    if isinstance(node, yaml.nodes.SequenceNode):
        for child in node.value:
            _reject_aliases(child)
    elif isinstance(node, yaml.nodes.MappingNode):
        for key_node, value_node in node.value:
            _reject_aliases(key_node)
            _reject_aliases(value_node)


class HostEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=253)
    scheme: Literal["http", "https"]
    ports: list[Port] = Field(min_length=1, max_length=64)
    addresses: list[str] = Field(default_factory=list)

    @field_validator("ports")
    @classmethod
    def unique_ports(cls, value: list[int]) -> list[int]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate ports")
        return value

    @model_validator(mode="after")
    def host_shape(self) -> HostEntry:
        try:
            host = normalize_host(self.host)
            pins = [normalize_host(item) for item in self.addresses]
        except NormalizationError as exc:
            raise ValueError(str(exc)) from exc
        if any(not is_ip(pin) for pin in pins):
            raise ValueError("address pins must be ip addresses")
        if len(pins) != len(set(pins)):
            raise ValueError("duplicate address pins")
        if is_ip(host):
            if pins and pins != [host]:
                raise ValueError("an ip host cannot pin a different address")
        elif not pins:
            raise ValueError("a hostname requires an explicit address pin set")
        return self


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    concurrency: int = Field(default=1, ge=1, le=8)
    rate_limit_rps: float = Field(default=2.0, gt=0, le=20)


class OpenRedirectSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parameter: str
    canary_url: str
    endpoints: list[str] = Field(min_length=1, max_length=32)

    @field_validator("parameter")
    @classmethod
    def parameter_token(cls, value: str) -> str:
        if _PARAM.match(value) is None:
            raise ValueError("parameter must be a short token of letters, digits, '_' or '-'")
        return value

    @field_validator("canary_url")
    @classmethod
    def canary_shape(cls, value: str) -> str:
        try:
            parsed = parse_http_url(value)
        except NormalizationError as exc:
            raise ValueError(f"canary_url: {exc}") from exc
        if parsed.scheme != "https":
            raise ValueError("canary_url must be https")
        if not parsed.host.endswith(".invalid"):
            raise ValueError("canary host must use the .invalid TLD")
        if parsed.path.rstrip("/") in {"", "/"}:
            raise ValueError("canary path must not be '/'")
        return parsed.canonical

    @field_validator("endpoints")
    @classmethod
    def endpoint_shape(cls, value: list[str]) -> list[str]:
        canonical: list[str] = []
        for item in value:
            try:
                canonical.append(parse_http_url(item).canonical)
            except NormalizationError as exc:
                raise ValueError(f"endpoint: {exc}") from exc
        if len(canonical) != len(set(canonical)):
            raise ValueError("duplicate open_redirect endpoints")
        return canonical


class DebugExposureSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    marker: str
    endpoints: list[str] = Field(min_length=1, max_length=32)

    @field_validator("marker")
    @classmethod
    def marker_shape(cls, value: str) -> str:
        if _MARKER.match(value) is None:
            raise ValueError(
                "marker must match SG_ followed by 6 to 64 uppercase letters, digits, or underscores"
            )
        return value

    @field_validator("endpoints")
    @classmethod
    def endpoint_shape(cls, value: list[str]) -> list[str]:
        canonical: list[str] = []
        for item in value:
            try:
                canonical.append(parse_http_url(item).canonical)
            except NormalizationError as exc:
                raise ValueError(f"endpoint: {exc}") from exc
        if len(canonical) != len(set(canonical)):
            raise ValueError("duplicate debug_exposure endpoints")
        return canonical


class OutputSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[Literal["json", "markdown"]] = Field(
        default_factory=lambda: ["json", "markdown"],
        min_length=1,
    )

    @field_validator("formats")
    @classmethod
    def unique_formats(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate output formats")
        return value


class AssessmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    hosts: list[HostEntry] = Field(min_length=1, max_length=32)
    path_prefixes: list[str] = Field(min_length=1, max_length=64)
    limits: Limits = Field(default_factory=Limits)
    recon: list[Literal["dns", "http", "tls"]] = Field(default_factory=list)
    checks: list[Literal["open_redirect", "debug_exposure"]] = Field(default_factory=list)
    open_redirect: OpenRedirectSettings | None = None
    debug_exposure: DebugExposureSettings | None = None
    output: OutputSettings = Field(default_factory=OutputSettings)
    allow_loopback: bool = True
    allow_private: bool = False
    allow_public: bool = False

    @field_validator("name")
    @classmethod
    def name_chars(cls, value: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("name contains control characters")
        return value

    @field_validator("path_prefixes")
    @classmethod
    def prefix_shape(cls, value: list[str]) -> list[str]:
        canonical: list[str] = []
        for item in value:
            try:
                canonical.append(normalize_path(item))
            except NormalizationError as exc:
                raise ValueError(str(exc)) from exc
        collapsed = [item.rstrip("/") or "/" for item in canonical]
        if len(collapsed) != len(set(collapsed)):
            raise ValueError("duplicate path prefixes")
        return canonical

    @field_validator("recon", "checks")
    @classmethod
    def unique_modules(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate module")
        return value

    @model_validator(mode="after")
    def module_settings(self) -> AssessmentConfig:
        if not self.recon and not self.checks:
            raise ValueError("enable at least one recon module or check")
        if "open_redirect" in self.checks and self.open_redirect is None:
            raise ValueError("open_redirect settings are required when the check is enabled")
        if "debug_exposure" in self.checks and self.debug_exposure is None:
            raise ValueError("debug_exposure settings are required when the check is enabled")
        if self.open_redirect is not None and "open_redirect" not in self.checks:
            raise ValueError("open_redirect settings are set but the check is not enabled")
        if self.debug_exposure is not None and "debug_exposure" not in self.checks:
            raise ValueError("debug_exposure settings are set but the check is not enabled")
        keys: list[tuple[str, str, int]] = []
        for entry in self.hosts:
            host = normalize_host(entry.host)
            for port in entry.ports:
                keys.append((host, entry.scheme, port))
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate host, scheme, and port")
        return self


def read_config_data(path: Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigError(f"config file not found: {file_path}")
    if file_path.stat().st_size > _MAX_CONFIG_BYTES:
        raise ConfigError("config file exceeds 1MB")
    text = file_path.read_text(encoding="utf-8")
    return parse_yaml(text)


def parse_yaml(text: str) -> dict[str, Any]:
    loader = _StrictLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            raise ConfigError("config is empty")
        _reject_aliases(node)
        data = loader.construct_document(node)
    except ConfigError:
        raise
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error: {exc}") from exc
    finally:
        loader.dispose()
    if not isinstance(data, dict):
        raise ConfigError("config must be a YAML mapping")
    return data


def parse_config(data: dict[str, Any]) -> AssessmentConfig:
    try:
        return AssessmentConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError("invalid configuration: " + _format_validation(exc)) from exc


def _format_validation(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(item) for item in err["loc"]) or "config"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)
