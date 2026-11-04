"""Per-GPU registry dwords kept in the profile's preserved NVreg_RegistryDwordsPerDevice parameter."""
from __future__ import annotations
from .config import BDF
from .security import LifecycleError

PARAMETER = "NVreg_RegistryDwordsPerDevice"


def scopes(value: str) -> dict[str, dict[str, str]]:
    """'pci=BDF;Key=value;...' -> {BDF: {Key: value}}, refusing anything outside that grammar."""
    result, scope = {}, None
    for field in filter(None, value.split(";")):
        key, separator, data = field.partition("=")
        if not separator or not key or not data or "=" in data:
            raise LifecycleError("malformed registry parameter")
        if key == "pci":
            if not BDF.fullmatch(data):
                raise LifecycleError("registry BDF must be canonical")
            scope = result.setdefault(data, {})
        elif scope is None:
            raise LifecycleError("registry key has no PCI scope")
        else:
            scope[key] = data
    return result


def with_value(parameters: dict, bdf: str, key: str, data: str | None) -> dict:
    """Copy of parameters with key set for bdf, or removed when data is None; empty scopes are dropped."""
    values = scopes(parameters.get(PARAMETER, ""))
    if data is None:
        values.get(bdf, {}).pop(key, None)
    else:
        values.setdefault(bdf, {})[key] = data
    text = ";".join(part for scope, entries in values.items() if entries
                    for part in ["pci=" + scope, *[f"{name}={value}" for name, value in entries.items()]])
    result = {name: value for name, value in parameters.items() if name != PARAMETER}
    if text:
        result[PARAMETER] = text
    return result
