"""Policy-as-code: which tools an agent may use, with which arguments, under which conditions.

A policy is a YAML file validated by Pydantic, so a typo in the policy is an error
rather than a silently ignored rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    PrivateAttr,
    StrictInt,
    StrictStr,
    create_model,
    field_validator,
)

EMAIL_PATTERN = r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"

Risk = Literal["low", "medium", "high"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArgSpec(_Strict):
    type: Literal["string", "integer", "number", "boolean"] = "string"
    description: str = ""
    required: bool = True
    # string constraints
    max_length: Optional[int] = None
    pattern: Optional[str] = Field(None, description="regex, or the shortcut 'email'")
    enum: Optional[list[Any]] = None
    # numeric constraints
    min: Optional[float] = None
    max: Optional[float] = None
    # semantic constraints
    path_within: Optional[list[str]] = Field(None, description="relative folders the path must stay inside")
    email_domains: Optional[list[str]] = Field(None, description="recipient domains that are allowed")
    egress: bool = Field(False, description="value is a URL the tool will fetch; must be on the egress allow-list")
    sql_readonly: bool = False
    scan: bool = Field(True, description="run content checks (injection, secrets...) on this argument")


class ToolRule(_Strict):
    description: str = ""
    enabled: bool = True
    risk: Risk = "low"
    requires_approval: bool = False
    rate_limit: Optional[int] = Field(None, description="max allowed calls per session")
    allow_extra_args: bool = False
    args: dict[str, ArgSpec] = Field(default_factory=dict)


class Defaults(_Strict):
    unknown_tools: Literal["deny", "review"] = "deny"
    scan_arguments: bool = True
    approval_for_risk: list[Risk] = Field(default_factory=lambda: ["high"])
    max_calls_per_session: Optional[int] = 50
    block_on_warnings: bool = False


class Egress(_Strict):
    allowed_domains: list[str] = Field(default_factory=list)


class Policy(_Strict):
    version: int = 1
    name: str = "unnamed-policy"
    description: str = ""
    defaults: Defaults = Field(default_factory=Defaults)
    egress: Egress = Field(default_factory=Egress)
    tools: dict[str, ToolRule] = Field(default_factory=dict)
    _models: dict[str, type[BaseModel]] = PrivateAttr(default_factory=dict)

    @field_validator("tools")
    @classmethod
    def _names(cls, v: dict[str, ToolRule]) -> dict[str, ToolRule]:
        for name in v:
            if not name.replace("_", "").replace("-", "").replace(".", "").isalnum():
                raise ValueError(f"invalid tool name {name!r}")
        return v

    # --- loading ---------------------------------------------------------------
    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("policy must be a YAML mapping")
        return cls.model_validate(data)

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def default(cls) -> "Policy":
        return cls.from_file(Path(__file__).parent / "policies" / "default.yaml")

    # --- compiled argument models ---------------------------------------------
    def arg_model(self, tool: str) -> type[BaseModel]:
        if tool not in self._models:
            self._models[tool] = build_arg_model(tool, self.tools[tool])
        return self._models[tool]


def _field_type(spec: ArgSpec):
    if spec.enum is not None:
        base: Any = Literal[tuple(spec.enum)]  # type: ignore[misc]
        return base, Field()
    if spec.type == "string":
        pattern = EMAIL_PATTERN if spec.pattern == "email" else spec.pattern
        return StrictStr, Field(max_length=spec.max_length, pattern=pattern)
    if spec.type == "integer":
        return StrictInt, Field(ge=spec.min, le=spec.max)
    if spec.type == "number":
        return StrictFloat, Field(ge=spec.min, le=spec.max)
    return StrictBool, Field()


def build_arg_model(tool: str, rule: ToolRule) -> type[BaseModel]:
    """Turn a tool's argument spec into a strict Pydantic model."""
    fields: dict[str, Any] = {}
    for name, spec in rule.args.items():
        typ, info = _field_type(spec)
        if spec.required:
            fields[name] = (Annotated[typ, info], ...)
        else:
            fields[name] = (Optional[Annotated[typ, info]], None)
    config = ConfigDict(extra="allow" if rule.allow_extra_args else "forbid", strict=True)
    model_name = "Args_" + "".join(ch if ch.isalnum() else "_" for ch in tool)
    return create_model(model_name, __config__=config, **fields)
